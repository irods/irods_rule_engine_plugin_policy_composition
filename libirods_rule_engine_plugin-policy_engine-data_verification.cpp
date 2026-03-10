
#include <irods/policy_composition_framework_policy_engine.hpp>
#include <irods/policy_composition_framework_parameter_capture.hpp>
#include <irods/policy_composition_framework_configuration_manager.hpp>

#include "data_verification_utilities.hpp"

namespace
{

	// clang-format off
    namespace pc   = irods::policy_composition;
    namespace pe   = irods::policy_composition::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    using     json = nlohmann::json;
	// clang-format on

	namespace verification
	{
		static const std::string catalog("catalog");
		static const std::string filesystem("filesystem");
		static const std::string checksum("checksum");
	} //namespace verification

	auto get_alternate_resource(
		rsComm_t* comm,
		const std::string& logical_path,
		const std::string& destination_resource) -> std::string
	{
		fs::path path{logical_path};
		const auto coll_name = path.parent_path();
		const auto data_name = path.object_name();

		// query for list of all participating resources
		auto qstr{fmt::format(
			"SELECT RESC_NAME WHERE COLL_NAME = '{}' AND DATA_NAME = '{}'", coll_name.string(), data_name.string())};

		irods::query qobj{comm, qstr};

		for (auto&& rn : qobj) {
			if (rn[0] != destination_resource) {
				return rn[0];
			}
		}

		THROW(SYS_INVALID_INPUT_PARAM, fmt::format("No alternate replica found for [{}]", logical_path));

	} // get_alternate_resource

	auto determine_source_and_destiation(
		rsComm_t* _comm,
		const std::string& _logical_path,
		const std::string& _source_resource,
		const std::string& _destination_resource)
	{
		auto src_flg = _source_resource.empty();
		auto dst_flg = _destination_resource.empty();

		if (src_flg && dst_flg) {
			THROW(SYS_INVALID_INPUT_PARAM, "source and destination resources cannot be empty");
		}

		auto src = _source_resource;
		auto dst = _destination_resource;

		if (src_flg) {
			src = get_alternate_resource(_comm, _logical_path, _destination_resource);
		}

		if (dst_flg) {
			dst = src;
			src = get_alternate_resource(_comm, _logical_path, _source_resource);
		}

		return std::make_tuple(src, dst);

	} // determine_source_and_destiation

	irods::error data_verification_policy(const pe::context& ctx, pe::arg_type out)
	{
		auto comm = ctx.rei->rsComm;

		std::string user_name{}, logical_path{}, source_resource{}, destination_resource{}, type{}, units{};

		std::tie(user_name, logical_path, source_resource, destination_resource) =
			capture_parameters(ctx.parameters, tag_first_resc);

		if (source_resource.empty()) {
			// may be statically configured
			source_resource = pc::get(ctx.configuration, "source_resource", source_resource);
		}

		std::tie(source_resource, destination_resource) =
			determine_source_and_destiation(comm, logical_path, source_resource, destination_resource);

		auto attribute = pc::get(ctx.configuration, "attribute", std::string{"irods::verification::type"});

		std::tie(type, units) = get_metadata_for_resource(comm, attribute, destination_resource);

		if (type.empty()) {
			type = verification::catalog;
		}

		pe::client_message(
			{{"0.usage",
		      fmt::format(
				  "{} requires user_name, logical_path, source_resource, and destination_resource", ctx.policy_name)},
		     {"1.user_name", user_name},
		     {"2.logical_path", logical_path},
		     {"3.source_resource", source_resource},
		     {"4.destination_resource", destination_resource},
		     {"5.type", type}});

		auto verif_fcn = [&](auto& comm) {
			return irods::verify_replica_for_destination_resource(
				&comm, type, logical_path, source_resource, destination_resource);
		};

		bool verified = false;

		try {
			verified = pc::exec_as_user(*comm, user_name, verif_fcn);
		}
		catch (const irods::exception& e) {
			auto msg = fmt::format(
				"irods_policy_data_verification type [{}] failed from [{}] to [{}]",
				type,
				source_resource,
				destination_resource);

			return ERROR(e.code(), msg);
		}

		if (verified) {
			return SUCCESS();
		}
		else {
			auto msg = fmt::format(
				"irods_policy_data_verification type [{}] failed from [{}] to [{}]",
				type,
				source_resource,
				destination_resource);
			return ERROR(UNMATCHED_KEY_OR_INDEX, msg);
		}

	} // data_verification_policy

} // namespace

const char usage[] = R"(
{
    "$id": "https://schemas.irods.org/policy-composition/data_verification.json",
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
	return pe::make(_plugin_name, "irods_policy_data_verification", usage, data_verification_policy);

} // plugin_factory
