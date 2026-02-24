
#include <irods/policy_composition_framework_policy_engine.hpp>
#include <irods/policy_composition_framework_parameter_capture.hpp>

#include <irods/irods_hierarchy_parser.hpp>
#include <irods/irods_server_api_call.hpp>

#include <irods/physPath.hpp>
#include <irods/apiNumber.h>

#include "parameter_substitution.hpp"

namespace
{

	// clang-format off
    namespace pc   = irods::policy_composition;
    namespace kw   = irods::policy_composition::keywords;
    namespace pe   = irods::policy_composition::policy_engine;
    using     json = nlohmann::json;
	// clang-format on

	auto destination_replica_exists(rsComm_t* comm, const std::string& resource, const std::string& logical_path)
	{
		namespace fs = irods::experimental::filesystem;

		fs::path path{logical_path};
		const auto coll_name = path.parent_path();
		const auto data_name = path.object_name();

		auto leaf_bundle = pe::compute_leaf_bundle(resource);

		auto qstr{boost::str(
			boost::format("SELECT DATA_REPL_NUM WHERE COLL_NAME = '%s' AND DATA_NAME = '%s' AND DATA_REPL_STATUS = '1' "
		                  "AND RESC_ID IN (%s)") %
			coll_name.string() % data_name.string() % leaf_bundle)};

		irods::query qobj{comm, qstr};

		return (qobj.size() > 0);

	} // destination_replica_exists

	auto replicate_object_to_resource(
		rsComm_t* _comm,
		const std::string& _user_name,
		const std::string& _logical_path,
		const std::string& _source_resource,
		const std::string& _destination_resource)
	{
		if (destination_replica_exists(_comm, _destination_resource, _logical_path)) {
			return 0;
		}

		dataObjInp_t data_obj_inp{};
		rstrcpy(data_obj_inp.objPath, _logical_path.c_str(), MAX_NAME_LEN);
		data_obj_inp.createMode = getDefFileMode();
		addKeyVal(&data_obj_inp.condInput, RESC_NAME_KW, _source_resource.c_str());
		addKeyVal(&data_obj_inp.condInput, DEST_RESC_NAME_KW, _destination_resource.c_str());

		if (_comm->clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH) {
			addKeyVal(&data_obj_inp.condInput, ADMIN_KW, "true");
		}

		transferStat_t* trans_stat{};

		auto repl_fcn = [&](auto& comm) {
			auto ret = irods::server_api_call(DATA_OBJ_REPL_AN, _comm, &data_obj_inp, &trans_stat);
			free(trans_stat);
			clearDataObjInp(&data_obj_inp);
			return ret;
		};

		return pc::exec_as_user(*_comm, _user_name, repl_fcn);

	} // replicate_object_to_resource

	auto replication_policy(const pe::context ctx, pe::arg_type out)
	{
		auto comm = ctx.rei->rsComm;

		auto [user_name, logical_path, source_resource, destination_resource] =
			capture_parameters(ctx.parameters, tag_first_resc);

		destination_resource = destination_resource.empty()
		                           ? pc::get(ctx.configuration, "destination_resource", std::string{})
		                           : destination_resource;

		pe::client_message(
			{{"0.usage",
		      fmt::format(
				  "{} requires user_name, logical_path, source_resource, destination_resource or "
				  "source_to_destination_map",
				  ctx.policy_name)},
		     {"1.user_name", user_name},
		     {"2.logical_path", logical_path},
		     {"3.source_resource", source_resource},
		     {"4.destination_resource", destination_resource}});

		if (!destination_resource.empty()) {
			pe::client_message(
				{{"0.message", fmt::format("{} destination_resource is not emtpy", ctx.policy_name)},
			     {"1.message",
			      fmt::format(
					  "{} replicating {} from {} to {}",
					  ctx.policy_name,
					  logical_path,
					  source_resource,
					  destination_resource)}});

			// direct call invocation
			int err =
				replicate_object_to_resource(comm, user_name, logical_path, source_resource, destination_resource);
			if (err < 0) {
				return ERROR(
					err,
					boost::format("failed to replicate [%s] from [%s] to [%s]") % logical_path % source_resource %
						destination_resource);
			}
		}
		else {
			pe::client_message(
				{{"0.message",
			      fmt::format(
					  "{} destination_resource is emtpy, requires source_to_destination_map", ctx.policy_name)}});

			if (ctx.configuration.find("source_to_destination_map") == ctx.configuration.end()) {
				THROW(
					SYS_INVALID_INPUT_PARAM,
					boost::format("%s - destination_resource or source_to_destination_map not provided") %
						ctx.policy_name);
			}

			auto src_dst_map{ctx.configuration.at("source_to_destination_map")};

			if (!src_dst_map.contains(source_resource)) {
				pc::logger::info(
					"{}: irods_policy_data_replication - source resource is not present in map [{}]",
					__func__,
					source_resource);
				return SUCCESS();
			}

			auto dst_resc_arr{src_dst_map.at(source_resource)};
			auto destination_resources = dst_resc_arr.get<std::vector<std::string>>();
			irods::error ret{SUCCESS()};

			for (auto& dest : destination_resources) {
				pe::client_message(
					{{"0.message",
				      fmt::format(
						  "{} replicating {} from {} to {}", ctx.policy_name, logical_path, source_resource, dest)}});

				int err = replicate_object_to_resource(comm, user_name, logical_path, source_resource, dest);
				if (err < 0) {
					ret = PASSMSG(
						boost::str(
							boost::format("failed to replicate [%s] from [%s] to [%s]") % logical_path %
							source_resource),
						ret);
				}
			}

			if (!ret.ok()) {
				return ret;
			}
		}

		return SUCCESS();

	} // replication_policy

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": ""
        "input_interfaces": [
            {
                "name" : "event_handler-collection_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-data_object_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-metadata_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-user_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-resource_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "direct_invocation",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "query_results"
                "description" : "",
                "json_schema" : ""
            },
        ],
    "output_json_for_validation" : ""
}
)";

extern "C" pe::plugin_pointer_type plugin_factory(const std::string& _plugin_name, const std::string&)
{
	return pe::make(_plugin_name, "irods_policy_data_replication", usage, replication_policy);
} // plugin_factory
