
#include <irods/policy_composition_framework_policy_engine.hpp>
#include <irods/policy_composition_framework_parameter_capture.hpp>
#include <irods/policy_composition_framework_configuration_manager.hpp>

#include <irods/rsModAVUMetadata.hpp>
#include <irods/irods_resource_backport.hpp>

#include <sys/statvfs.h>
#include <boost/filesystem.hpp>

namespace
{

	// clang-format off
    namespace pc   = irods::policy_composition;
    namespace pe   = irods::policy_composition::policy_engine;
    using     json = nlohmann::json;
	// clang-format on

	auto get_vault_path(const std::string& name) -> std::string
	{
		rodsLong_t resc_id = 0;
		auto err = resc_mgr.hier_to_leaf_id(name, resc_id);
		if (!err.ok()) {
			THROW(err.code(), err.result());
		}

		std::string vp{};

		err = irods::get_resource_property<std::string>(resc_id, irods::RESOURCE_PATH, vp);
		if (!err.ok()) {
			THROW(err.code(), err.result());
		}

		return vp;

	} // get_vault_path

	irods::error filesystem_usage(const pe::context& ctx, pe::arg_type out)
	{
		auto [un, lp, source_resource, dr] = capture_parameters(ctx.parameters, tag_first_resc);

		auto vault_path = get_vault_path(source_resource);

		pe::client_message(
			{{"0.usage", fmt::format("{} requires source_resource", ctx.policy_name)}, {"1.vault_path", vault_path}});

		boost::filesystem::path path_to_stat{vault_path};
		while (!boost::filesystem::exists(path_to_stat)) {
			pc::logger::info("{}: path to stat [{}] doesn't exist, moving to parent", __func__, path_to_stat.c_str());
			path_to_stat = path_to_stat.parent_path();
			if (path_to_stat.empty()) {
				auto msg =
					fmt::format("{}: could not find existing path from given path path [{}]", __func__, vault_path);
				pc::logger::error(msg);
				return ERROR(SYS_INVALID_RESC_INPUT, msg);
			}
		}

		struct statvfs statvfs_buf;
		const int statvfs_ret = statvfs(path_to_stat.string().c_str(), &statvfs_buf);
		if (statvfs_ret != 0) {
			auto msg = fmt::format(
				"[{}]: statvfs() of [{}] failed with return {} and errno {}",
				__FUNCTION__,
				path_to_stat.string(),
				statvfs_ret,
				errno);
			return ERROR(SYS_INVALID_RESC_INPUT, msg);
		}

		uint64_t free_space_blocks = static_cast<uint64_t>(statvfs_buf.f_bavail);
		uint64_t total_space_blocks = static_cast<uint64_t>(statvfs_buf.f_blocks);

		double percent_used =
			100.0 * (1.0 - static_cast<double>(free_space_blocks) / static_cast<double>(total_space_blocks));
		std::string percent_used_str = std::to_string(percent_used);

		modAVUMetadataInp_t set_op{};
		set_op.arg0 = "set";
		set_op.arg1 = "-R";
		set_op.arg2 = const_cast<char*>(source_resource.c_str());
		set_op.arg3 = "irods::resource::filesystem_percent_used";
		set_op.arg4 = const_cast<char*>(percent_used_str.c_str());

		auto status = rsModAVUMetadata(ctx.rei->rsComm, &set_op);
		if (status < 0) {
			return ERROR(
				status, fmt::format("Failed to assign filesystem usage metadata for resource [%s]", source_resource));
		}

		return SUCCESS();

	} // filesystem_usage

} // namespace

const char usage[] = R"(
{
    "$id": "https://schemas.irods.org/policy-composition/filesystem_usage.json",
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
	return pe::make(_plugin_name, "irods_policy_filesystem_usage", usage, filesystem_usage);
} // plugin_factory
