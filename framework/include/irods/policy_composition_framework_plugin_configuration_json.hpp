#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON_HPP
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_PLUGIN_CONFIGURATION_JSON_HPP

#include <string>
#include <vector>

#include <irods/rcMisc.h>
#include <irods/irods_get_full_path_for_config_file.hpp>
#include <irods/irods_server_properties.hpp>

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
				rodsLog(LOG_NOTICE, "get_full_path_for_config_file failed for server_config");
				return {};
			}

			rodsLog(LOG_DEBUG, "[%s] Loading [%s]", _instance_name.c_str(), cfg_file.c_str());

			std::ifstream ifn(cfg_file.c_str());
			if (!ifn.is_open()) {
				rodsLog(LOG_ERROR, "[%s] failed to open [%s]", _instance_name.c_str(), cfg_file.c_str());
				return {};
			}

			json server_config;
			server_config = json::parse(ifn);
			ifn.close();

			if (server_config.empty()) {
				rodsLog(LOG_ERROR, "[%s] empty server config json object", _instance_name.c_str());
				return {};
			}

			auto reps = server_config["plugin_configuration"]["rule_engines"];
			if (reps.empty()) {
				rodsLog(LOG_ERROR, "[%s] empty rule engine plugin json array", _instance_name.c_str());
				return {};
			}

			for (auto& rep : reps) {
				if (rep["instance_name"] == _instance_name) {
					return rep["plugin_specific_configuration"];
				}
			}
		}
		catch (const json::exception& e) {
			rodsLog(
				LOG_ERROR,
				"[%s] Exception Caught parsing JSON configuration for plugin instance [%s]",
				_instance_name.c_str(),
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
