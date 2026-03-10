#include <irods/policy_composition_framework_policy_engine.hpp>
#include <irods/policy_composition_framework_parameter_capture.hpp>

#include <irods/apiNumber.h>
#include <irods/irods_server_api_call.hpp>
#include <irods/irods_resource_manager.hpp>
#include <irods/irods_hierarchy_parser.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <iostream>

#include "parameter_substitution.hpp"

extern irods::resource_manager resc_mgr;

namespace
{

	// clang-format off
    namespace pc                  = irods::policy_composition;
    namespace fs                  = irods::experimental::filesystem;
    namespace kw                  = irods::policy_composition::keywords;
    namespace pe                  = irods::policy_composition::policy_engine;
    using     string_vector       = std::vector<std::string>;
    using     string_tuple_vector = std::vector<std::tuple<std::string, std::string>>;
	// clang-format on

	namespace retention_mode
	{
		static const std::string remove_all{"remove_all_replicas"};
		static const std::string trim_single{"trim_single_replica"};
	}; //namespace retention_mode

	auto mode_is_supported(const std::string& m) -> bool
	{
		return (m == retention_mode::remove_all || m == retention_mode::trim_single);
	}

	auto get_source_resource(rsComm_t* comm, const std::string& logical_path, const std::string& destination_resource)
		-> std::string
	{
		fs::path path{logical_path};
		const auto coll_name = path.parent_path();
		const auto data_name = path.object_name();

		// query for list of all participating resources
		auto qstr{boost::str(
			boost::format("SELECT RESC_NAME WHERE COLL_NAME = '%s' AND DATA_NAME = '%s'") % coll_name.string() %
			data_name.string())};

		irods::query qobj{comm, qstr};

		// if there are more than two replicas and no source resource has been
		// specificied, this is a usage error
		if (qobj.size() > 2) {
			THROW(
				SYS_INVALID_INPUT_PARAM,
				fmt::format("Multiple replicas found with no specified source resource for [{}]", logical_path));
		}

		for (auto&& rn : qobj) {
			if (rn[0] != destination_resource) {
				return rn[0];
			}
		}

		THROW(SYS_INVALID_INPUT_PARAM, fmt::format("No source replica found for [{}]", logical_path));

	} // get_source_resource

	auto get_replica_number_for_resource(
		rsComm_t* comm,
		const std::string& logical_path,
		const std::string& source_resource) -> std::string
	{
		fs::path path{logical_path};
		const auto coll_name = path.parent_path();
		const auto data_name = path.object_name();

		// query for list of all participating resources
		auto qstr{boost::str(
			boost::format("SELECT DATA_REPL_NUM WHERE COLL_NAME = '%s' AND DATA_NAME = '%s' AND RESC_NAME = '%s'") %
			coll_name.string() % data_name.string() % source_resource)};

		irods::query qobj{comm, qstr};

		return qobj.size() > 0 ? qobj.front()[0] : "INVALID_REPLICA_NUMBER";

	} // get_replica_number_for_resource

	auto remove_data_object(
		int api_index,
		rsComm_t* comm,
		const std::string& user_name,
		const std::string& logical_path,
		const std::string& source_resource = {}) -> int
	{
		dataObjInp_t obj_inp{};
		memset(&obj_inp, 0, sizeof(obj_inp));
		rstrcpy(obj_inp.objPath, logical_path.c_str(), sizeof(obj_inp.objPath));

		if (comm->clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH) {
			addKeyVal(&obj_inp.condInput, ADMIN_KW, "true");
		}

		addKeyVal(&obj_inp.condInput, COPIES_KW, "1");

		std::string repl_num{};

		if (!source_resource.empty()) {
			repl_num = get_replica_number_for_resource(comm, logical_path, source_resource);
			addKeyVal(&obj_inp.condInput, REPL_NUM_KW, repl_num.c_str());
		}

		auto trim_fcn = [&](auto& comm) {
			auto res{irods::server_api_call(api_index, &comm, &obj_inp)};
			clearDataObjInp(&obj_inp);
			return res;
		};

		return pc::exec_as_user(*comm, user_name, trim_fcn);

	} // remove_data_object

	auto get_leaf_resources_for_object(rsComm_t* comm, const std::string& logical_path) -> string_vector
	{
		namespace fs = irods::experimental::filesystem;

		fs::path path{logical_path};
		const auto coll_name = path.parent_path();
		const auto data_name = path.object_name();

		// query for list of all participating resources
		auto qstr{boost::str(
			boost::format("SELECT RESC_NAME WHERE COLL_NAME = '%s' AND DATA_NAME = '%s'") % coll_name.string() %
			data_name.string())};

		irods::query qobj{comm, qstr};

		string_vector resources{};
		for (auto r : qobj) {
			resources.push_back(r[0]);
		}

		return resources;

	} // get_leaf_resources_for_object

	auto get_leaf_resource_for_root(rsComm_t* comm, const std::string& source_resource, const std::string& logical_path)
		-> std::string
	{
		namespace fs = irods::experimental::filesystem;

		fs::path path{logical_path};
		const auto coll_name = path.parent_path();
		const auto data_name = path.object_name();

		auto leaf_bundle = pe::compute_leaf_bundle(source_resource);

		auto qstr{boost::str(
			boost::format("SELECT RESC_NAME WHERE COLL_NAME = '%s' AND DATA_NAME = '%s' AND RESC_ID IN (%s)") %
			coll_name.string() % data_name.string() % leaf_bundle)};

		irods::query qobj{comm, qstr};

		return qobj.size() > 0 ? qobj.front()[0] : std::string{};

	} // get_leaf_resource_for_root

	auto get_root_resources_for_leaves(rsComm_t* comm, const string_vector& leaf_resources)
	{
		std::vector<std::tuple<std::string, std::string>> roots_and_leaves;
		for (auto&& l : leaf_resources) {
			std::string hier{};
			irods::error err = resc_mgr.get_hier_to_root_for_resc(l, hier);

			irods::hierarchy_parser p(hier);
			roots_and_leaves.push_back(std::make_tuple(p.first_resc(), l));
		}

		return roots_and_leaves;

	} // get_root_resources_for_leaves

	auto filter_roots_and_leaves_by_whitelist(
		const string_vector& whitelist,
		const string_tuple_vector& roots_and_leaves)
	{
		if (whitelist.empty()) {
			return roots_and_leaves;
		}

		string_tuple_vector tmp{};
		for (auto&& rl : roots_and_leaves) {
			if (std::find(whitelist.begin(), whitelist.end(), std::get<0>(rl)) != whitelist.end()) {
				tmp.push_back(rl);
			}
		}

		return tmp;

	} // filter_roots_and_leaves_by_whitelist

	bool resource_has_preservation_metadata(rsComm_t* comm, const std::string& attribute, const std::string& resource)
	{
		auto qstr = boost::str(
			boost::format("SELECT META_RESC_ATTR_VALUE WHERE RESC_NAME = '%s' AND META_RESC_ATTR_NAME = '%s'") %
			resource % attribute);
		irods::query qobj{comm, qstr};

		return qobj.size() != 0;

	} // resource_has_preservation_metadata

	auto filter_roots_and_leaves_by_preservation_metadata(
		rsComm_t* comm,
		const std::string& attribute,
		const string_tuple_vector& roots_and_leaves)
	{
		string_tuple_vector tmp{};
		for (auto&& rl : roots_and_leaves) {
			if (!resource_has_preservation_metadata(comm, attribute, std::get<0>(rl))) {
				tmp.push_back(rl);
			}
		}

		return tmp;

	} // filter_roots_and_leaves_by_preservation_metadata

	auto determine_resource_list_for_unlink(
		rsComm_t* comm,
		const std::string& attribute,
		const std::string& logical_path,
		const string_vector& whitelist)
	{
		// need to convert leaves to roots and then determine if
		// 1. it is in the white list
		// 2. if it has preservation metadata

		auto leaf_resources = get_leaf_resources_for_object(comm, logical_path);
		auto roots_and_leaves = get_root_resources_for_leaves(comm, leaf_resources);
		roots_and_leaves = filter_roots_and_leaves_by_whitelist(whitelist, roots_and_leaves);
		roots_and_leaves = filter_roots_and_leaves_by_preservation_metadata(comm, attribute, roots_and_leaves);

		// gather remaining leaves
		string_vector tmp{};
		for (auto&& rl : roots_and_leaves) {
			tmp.push_back(std::get<1>(rl));
		}

		// if identical to original list then we unlink, not trim
		auto unlink = (leaf_resources == tmp);

		return std::make_tuple(unlink, tmp);

	} // determine_resource_list_for_unlink

	auto object_can_be_trimmed(
		rsComm_t* comm,
		const std::string& attribute,
		const std::string& source_resource,
		const string_vector& whitelist)
	{
		if (!whitelist.empty()) {
			if (std::find(whitelist.begin(), whitelist.end(), source_resource) == whitelist.end()) {
				return false;
			}
		}

		return !resource_has_preservation_metadata(comm, attribute, source_resource);

	} // object_can_be_trimmed

	auto data_retention_policy(const pe::context& ctx, pe::arg_type out)
	{
		auto mode = pc::get(ctx.configuration, "mode", std::string{});

		if (!mode_is_supported(mode)) {
			return ERROR(SYS_INVALID_INPUT_PARAM, boost::format("retention mode is not supported [%s]") % mode);
		}

		auto [user_name, logical_path, source_resource, destination_resource] =
			capture_parameters(ctx.parameters, tag_first_resc);

		pe::client_message(
			{{"0.usage",
		      fmt::format(
				  "{} requires user_name, logical_path, source_resource, or destination_resource and mode",
				  ctx.policy_name)},
		     {"1.user_name", user_name},
		     {"2.logical_path", logical_path},
		     {"3.source_resource", source_resource},
		     {"4.destination_resource", destination_resource},
		     {"5.mode", mode}});

		auto comm = ctx.rei->rsComm;
		auto whitelist = pc::get(ctx.configuration, "resource_white_list", json::array());
		auto attribute = pc::get(ctx.configuration, kw::attribute, std::string{"irods::retention::preserve_replicas"});

		if (mode == retention_mode::remove_all) {
			pe::client_message({{"0.message", fmt::format("{} mode is removing all replicas", ctx.policy_name)}});

			auto [unlink, resources_to_remove] =
				determine_resource_list_for_unlink(comm, attribute, logical_path, whitelist);

			pe::client_message({{"0.message", fmt::format("{} unlink flag is {}", ctx.policy_name, unlink)}});

			// removing all replicas requires a call to unlink, cannot trim
			if (unlink) {
				pe::client_message(
					{{"0.message", fmt::format("{} removing data object {}", ctx.policy_name, unlink, logical_path)}});

				const auto ret = remove_data_object(DATA_OBJ_UNLINK_AN, comm, user_name, logical_path);
				if (ret < 0) {
					return ERROR(
						ret, boost::format("failed to remove [%s] from [%s]") % logical_path % source_resource);
				}
			}
			// trim a specific list of replicas determined by policy
			else {
				for (const auto& src : resources_to_remove) {
					pe::client_message(
						{{"0.message",
					      fmt::format("{} trimming replica {} from {}", ctx.policy_name, unlink, logical_path, src)}});

					const auto ret = remove_data_object(DATA_OBJ_TRIM_AN, comm, user_name, logical_path, src);
					if (ret < 0) {
						return ERROR(ret, boost::format("failed to remove [%s] from [%s]") % logical_path % src);
					}
				} // for src
			}
		}
		// trim single replica
		else {
			if (source_resource.empty()) {
				source_resource = get_source_resource(comm, logical_path, destination_resource);
			}

			pe::client_message(
				{{"0.message",
			      fmt::format("{} mode is trimming single replica from {}", ctx.policy_name, source_resource)}});

			if (object_can_be_trimmed(comm, attribute, source_resource, whitelist)) {
				auto leaf_name = std::string{};

				leaf_name = get_leaf_resource_for_root(comm, source_resource, logical_path);

				pe::client_message(
					{{"0.message",
				      fmt::format("{} trimming single replica {} from {}", ctx.policy_name, logical_path, leaf_name)}});

				const auto ret = remove_data_object(DATA_OBJ_TRIM_AN, comm, user_name, logical_path, leaf_name);
				if (ret < 0) {
					return ERROR(
						ret, boost::format("failed to remove [%s] from [%s]") % logical_path % source_resource);
				}
			}
		}

		return SUCCESS();

	} // data_retention_policy

} // namespace

const char usage[] = R"(
{
    "$id": "https://schemas.irods.org/policy-composition/data_retention.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
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
	return pe::make(_plugin_name, "irods_policy_data_retention", usage, data_retention_policy);

} // plugin_factory
