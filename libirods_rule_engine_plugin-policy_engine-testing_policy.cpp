
#include <irods/policy_composition_framework_policy_engine.hpp>
#include <irods/policy_composition_framework_parameter_capture.hpp>
#include <irods/policy_composition_framework_configuration_manager.hpp>

#include <irods/rsModAVUMetadata.hpp>

#undef IRODS_METADATA_ENABLE_SERVER_SIDE_API
#define IRODS_METADATA_ENABLE_SERVER_SIDE_API
#include <irods/metadata.hpp>

#include <irods/policy_composition_framework_event_handler.hpp>

namespace
{

	// clang-format off
    namespace pc   = irods::policy_composition;
    namespace kw   = irods::policy_composition::keywords;
    namespace pe   = irods::policy_composition::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;
    using     json = nlohmann::json;
	// clang-format on

	const std::map<std::string, std::string> type_to_token{
		{kw::collection, "-C"},
		{kw::data_object, "-d"},
		{kw::user, "-u"},
		{kw::resource, "-R"}};

	auto type_to_entity(const std::string& _type, json _params)
	{
		const std::map<std::string, std::string> type_to_index{
			{kw::collection, kw::logical_path},
			{kw::data_object, kw::logical_path},
			{kw::user, kw::user_name},
			{kw::resource, kw::source_resource}};

		auto idx = type_to_index.at(_type);

		return _params.at(idx).get<std::string>();

	} // type_to_entity

	irods::error testing_policy(const pe::context& ctx, pe::arg_type out)
	{
		std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

		pc::logger::info(
			"{}: PARAMETERS\n--------\n{}\n--------",
			__func__,
			ctx.parameters.dump(4, ' ', false, json::error_handler_t::replace));

		if (ctx.parameters.contains("query_results")) {
			using fsp = irods::experimental::filesystem::path;
			std::string tmp_coll_name{}, tmp_data_name{};

			auto query_results = ctx.parameters.at("query_results").get<std::vector<std::string>>();
			//user_name       = query_results[0];
			tmp_coll_name = query_results[1];
			tmp_data_name = query_results[2];
			//source_resource = query_results[3];

			logical_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
		}
		else {
			std::tie(user_name, logical_path, source_resource, destination_resource) =
				capture_parameters(ctx.parameters, tag_first_resc);
		}

		auto comm = ctx.rei->rsComm;

		std::string event{"unspecified"};
		if (ctx.parameters.contains(kw::event)) {
			event = ctx.parameters.at(kw::event);
		}

		std::string entity_type, option, target;
		modAVUMetadataInp_t set_op{};
		if ("METADATA" == event) {
			if (ctx.parameters.contains(kw::conditional)) {
				if (ctx.parameters.contains(kw::metadata)) {
					if (ctx.parameters.at(kw::conditional).at(kw::metadata).contains(kw::entity_type)) {
						entity_type = ctx.parameters.at(kw::conditional).at(kw::metadata).at(kw::entity_type);
					}
				}
			}
			else if (ctx.parameters.contains(kw::metadata)) {
				if (ctx.parameters.at(kw::metadata).contains(kw::entity_type)) {
					entity_type = ctx.parameters.at(kw::metadata).at(kw::entity_type);
				}
			}
			else {
				return ERROR(SYS_INVALID_INPUT_PARAM, "testing_policy :: missing 'entity_type' in 'metadata'");
			}

			option = type_to_token.at(entity_type);
			target = type_to_entity(entity_type, ctx.parameters);
		}
		else if (!logical_path.empty()) {
			target = logical_path;

			if (!fsvr::exists(*comm, target)) {
				target = fs::path(target).parent_path();
			}

			option = fsvr::is_data_object(*comm, target) ? "-d" : "-C";
		}
		else if (!source_resource.empty()) {
			target = (event == "REMOVE") ? "demoResc" : source_resource;
			option = "-R";
		}
		else if (!user_name.empty()) {
			target = (event == "REMOVE") ? "rods" : user_name;
			option = "-u";
		}

		set_op.arg0 = "add";
		set_op.arg1 = const_cast<char*>(option.c_str());
		set_op.arg2 = const_cast<char*>(target.c_str());
		set_op.arg3 = "irods_policy_testing_policy";
		set_op.arg4 = const_cast<char*>(event.c_str());

		auto status = rsModAVUMetadata(comm, &set_op);
		if (status < 0) {
			return ERROR(
				status,
				boost::format("Failed to invoke test_policy for [%s] with metadata [%s] [%s]") % target %
					"irods_testing_policy" % event);
		}

		return SUCCESS();

	} // testing_policy

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "This is a test, this is only a test."
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
	return pe::make(_plugin_name, "irods_policy_testing_policy", usage, testing_policy);
} // plugin_factory
