#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON_HPP
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON_HPP

#include <fstream>
#include <string>
#include <vector>

#include <irods/rcMisc.h>
#include <irods/irods_get_full_path_for_config_file.hpp>
#include <irods/irods_server_properties.hpp>

#include <irods/policy_composition_framework_logging_category.hpp>

#include <nlohmann/json.hpp>

namespace irods
{

	using json = nlohmann::json;

	inline auto get_plugin_specific_configuration(const std::string& _instance_name) -> json
	{
		try {
			std::string cfg_file{};
			error ret = get_full_path_for_config_file(SERVER_CONFIG_FILE, cfg_file);
			if (!ret.ok()) {
				irods::policy_composition::logger::info(
					"{}: get_full_path_for_config_file failed for server_config", __func__);
				return {};
			}

			irods::policy_composition::logger::debug("{}: {} Loading {}", __func__, _instance_name, cfg_file);

			std::ifstream ifn(cfg_file.c_str());
			if (!ifn.is_open()) {
				irods::policy_composition::logger::error(
					"{}: [{}] failed to open [{}].", __func__, _instance_name, cfg_file);
				return {};
			}

			json server_config;
			server_config = json::parse(ifn);
			ifn.close();

			if (server_config.empty()) {
				irods::policy_composition::logger::error(
					"{}: [{}] empty server config json object", __func__, _instance_name);
				return {};
			}

			auto reps = server_config["plugin_configuration"]["rule_engines"];
			if (reps.empty()) {
				irods::policy_composition::logger::error(
					"{}: [{}] empty rule engine plugin json array", __func__, _instance_name);
				return {};
			}

			for (auto& rep : reps) {
				if (rep["instance_name"] == _instance_name) {
					return rep["plugin_specific_configuration"];
				}
			}
		}
		catch (const json::exception& e) {
			irods::policy_composition::logger::error(
				"{}: [{}] Exception caught parsing JSON configuration for plugin instance [{}]",
				__func__,
				_instance_name,
				e.what());
		}

		return {};

	} // get_plugin_specific_configuration

	struct plugin_configuration_json
	{
		json plugin_configuration;

		explicit plugin_configuration_json(const std::string& _instance_name)
		{
			plugin_configuration = get_plugin_specific_configuration(_instance_name);
		}

	}; // struct plugin_configuration

} // namespace irods

#endif // IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON_HPP
