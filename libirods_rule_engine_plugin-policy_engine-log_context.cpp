
#include <irods/policy_composition_framework_policy_engine.hpp>
#include <irods/policy_composition_framework_parameter_capture.hpp>
#include <irods/policy_composition_framework_configuration_manager.hpp>

#include <irods/filesystem.hpp>
#include <irods/rsModAVUMetadata.hpp>
#include <irods/rsOpenCollection.hpp>
#include <irods/rsReadCollection.hpp>
#include <irods/rsCloseCollection.hpp>

namespace
{

	// clang-format off
    namespace pc   = irods::policy_composition;
    namespace pe   = irods::policy_composition::policy_engine;
    using     json = nlohmann::json;
	// clang-format on

	irods::error log_context(const pe::context& ctx, pe::arg_type out)
	{
		pc::logger::debug(
			"{}: PARAMETERS: [{}]\nCONFIGURATION: [{}]",
			__func__,
			ctx.parameters.dump(4, ' ', false, json::error_handler_t::replace),
			ctx.configuration.dump(4, ' ', false, json::error_handler_t::replace));

		return SUCCESS();

	} // log_context

} // namespace

const char usage[] = R"(
{
    "$id": "https://schemas.irods.org/policy-composition/log_context.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
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
	return pe::make(_plugin_name, "irods_policy_log_context", usage, log_context);
} // plugin_factory
