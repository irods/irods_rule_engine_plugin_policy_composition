#include <irods/policy_composition_framework_policy_engine.hpp>

namespace pe = irods::policy_composition::policy_engine;

const char usage[] = R"(
{
    "$id": "https://schemas.irods.org/policy-composition/policy_engine_usage.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "input_interfaces": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "enum": [
                        "event_handler-collection_modified",
                        "event_handler-data_object_modified",
                        "event_handler-metadata_modified",
                        "event_handler-user_modified",
                        "event_handler-resource_modified",
                        "direct_invocation",
                        "query_results"
                    ]},
                    "description": {"type": "string"},
                    "json_schema": {"type": "string"}
                },
                "required": ["name","description","json_schema"]
            }
        },
        "output_json_for_validation": {"type": "string"}
    },
    "required": [
        "description",
        "input_interfaces",
        "output_json_for_validation"
    ]
}
)";

irods::error example_policy(const pe::context& ctx, pe::arg_type out)
{
	//  struct context {
	//      ruleExecInfo_t* rei{};
	//      std::string     instance_name{};
	//      std::string     policy_name{};
	//      json            parameters{};
	//      json            configuration{};
	//  }; // struct context

	*out = "Hello, World! from the example policy engine";

	rodsLog(LOG_NOTICE, "[%s]::[%s]", ctx.instance_name.c_str(), ctx.policy_name.c_str());
	return SUCCESS();
} // example_policy

extern "C" pe::plugin_pointer_type plugin_factory(const std::string& _plugin_name, const std::string&)
{
	return pe::make(_plugin_name, "irods_policy_engine_example", usage, example_policy);

} // plugin_factory
