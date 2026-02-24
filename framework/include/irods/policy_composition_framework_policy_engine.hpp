#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_POLICY_ENGINE_HPP
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_POLICY_ENGINE_HPP

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/rcMisc.h>

#define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include <irods/irods_query.hpp>

#include <boost/any.hpp>
#include <nlohmann/json.hpp>
#include <fmt/format.h>

#include "policy_composition_framework_utilities.hpp"
#include "policy_composition_framework_plugin_configuration_json.hpp"

namespace irods::policy_composition::policy_engine
{

	// clang-format off
    namespace pc   = irods::policy_composition;
    using     json = nlohmann::json;

    struct context {
        ruleExecInfo_t* rei{};
        std::string     usage_text{};
        std::string     instance_name{};
        std::string     policy_name{};
        std::string     policy_usage{};
        json            parameters{};
        json            configuration{};
    }; // struct context

    using arg_type            = std::string*;
    using plugin_type         = pluggable_rule_engine<irods::default_re_ctx>;
    using plugin_pointer_type = plugin_type*;
    using implementation_type = std::function<error(const context&, arg_type)>;

    auto                log_errors{false};
    json                plugin_config;
    context             policy_context;
    implementation_type policy_implementation;
	// clang-format on

	namespace
	{
		auto start(default_re_ctx&, const std::string&) -> error
		{
			RuleExistsHelper::Instance()->registerRuleRegex(policy_context.policy_name + ".*");
			return SUCCESS();
		}

		auto stop(default_re_ctx&, const std::string&) -> error
		{
			return SUCCESS();
		}

		auto rule_name_is_supported(const std::string& _rule_name) -> bool
		{
			auto supported = (policy_context.policy_name == _rule_name || policy_context.policy_usage == _rule_name);

			return supported;

		} // rule_name_is_supported

		auto rule_exists(default_re_ctx&, const std::string& _rule_name, bool& _return_value) -> error
		{
			_return_value = rule_name_is_supported(_rule_name);
			return SUCCESS();
		}

		auto list_rules(default_re_ctx&, std::vector<std::string>& _rules) -> error
		{
			_rules.push_back(policy_context.policy_name);
			_rules.push_back(policy_context.policy_usage);
			return SUCCESS();
		}

		auto get_log_errors_flag(const json& _params, const json& _config) -> bool
		{
			bool flag = false;
			if (!_params.empty()) {
				flag = (_params.find("log_errors") != _params.end());
			}

			if (!flag && !_config.empty()) {
				flag = (_config.find("log_errors") != _config.end());
			}

			return flag;

		} // get_log_errors_flag

		auto client_message(const json& _msg) -> void
		{
			if (!log_errors) {
				return;
			}

			addRErrorMsg(
				&policy_context.rei->rsComm->rError,
				0,
				_msg.dump(4, ' ', false, json::error_handler_t::replace).c_str());

			logger::info("{}: {}", __func__, _msg.dump(4, ' ', false, json::error_handler_t::replace));
		} // details

		error
		exec_rule(default_re_ctx&, const std::string& _rule_name, std::list<boost::any>& _arguments, callback _eff_hdlr)
		{
			ruleExecInfo_t* rei{};
			const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);
			if (!err.ok()) {
				return ERROR(SYS_NOT_SUPPORTED, err.result());
			}

			try {
				if (policy_context.policy_usage == _rule_name) {
					auto it = _arguments.begin();

					std::advance(it, 2);

					auto* out = boost::any_cast<arg_type>(*it);

					*out = policy_context.usage_text;

					return SUCCESS();
				}
				else if (policy_context.policy_name == _rule_name) {
					policy_context.rei = rei;

					auto it = _arguments.begin();
					auto* parameters = boost::any_cast<std::string*>(*it);
					++it;
					auto* configuration = boost::any_cast<std::string*>(*it);
					++it;
					auto* out_variable = boost::any_cast<std::string*>(*it);

					if (!parameters->empty()) {
						policy_context.parameters = json::parse(*parameters);
					}

					policy_context.configuration = plugin_config;
					if (!configuration->empty()) {
						// combine policy config and plugin specific config
						auto j = json::parse(*configuration);

						for (auto&& [k, v] : j.items()) {
							policy_context.configuration[k] = v;
						}
					}

					log_errors = get_log_errors_flag(policy_context.parameters, policy_context.configuration);

					auto err = policy_implementation(policy_context, out_variable);

					if (!err.ok()) {
						// support for stop_on_error behavior
						*out_variable = pc::error_to_json(err).dump(4, ' ', false, json::error_handler_t::replace);

						addRErrorMsg(&rei->rsComm->rError, err.code(), err.result().c_str());

						if (log_errors) {
							logger::error("{}: {}", __func__, err.result());
						}

						THROW(err.code(), err.result());
					}
				}
			}
			catch (const std::invalid_argument& _e) {
				if (log_errors) {
					logger::error("{}: invalid argument exception [{}]", __func__, _e.what());
				}
				pc::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const boost::bad_any_cast& _e) {
				if (log_errors) {
					logger::error("{}: bad any cast exception [{}]", __func__, _e.what());
				}
				pc::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const exception& _e) {
				if (log_errors) {
					logger::error("{}: exception caught [{}]", __func__, _e.client_display_what());
				}
				pc::exception_to_rerror(_e, rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const json::exception& _e) {
				addRErrorMsg(&rei->rsComm->rError, SYS_NOT_SUPPORTED, _e.what());
				if (log_errors) {
					logger::error("{}: json exception [{}]", __func__, _e.what());
				}
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (...) {
				const std::string msg{"policy_engine :: an unknown error has occurred."};
				addRErrorMsg(&rei->rsComm->rError, SYS_NOT_SUPPORTED, msg.c_str());
				logger::error("{}: {}", __func__, msg);
				return ERROR(SYS_NOT_SUPPORTED, msg);
			}

			// given that this is a specific policy implementation which does not react
			// to policy enforcement points we can return SUCCESS() rather than
			// CODE(RULE_ENGINE_CONTINUE), as there should only be one policy engine configured
			return SUCCESS();

		} // exec_rule

		error exec_rule_text(default_re_ctx&, const std::string&, msParamArray_t*, const std::string&, callback)
		{
			return ERROR(RULE_ENGINE_CONTINUE, "exec_rule_text is not supported");
		} // exec_rule_text

		error exec_rule_expression(default_re_ctx&, const std::string&, msParamArray_t*, callback)
		{
			return ERROR(RULE_ENGINE_CONTINUE, "exec_rule_expression is not supported");
		} // exec_rule_expression

	} // namespace

	inline plugin_pointer_type make(
		const std::string& _plugin_name,
		const std::string& _policy_name,
		const std::string& _usage_text,
		implementation_type _policy_implementation)
	{
		policy_implementation = _policy_implementation;
		policy_context.usage_text = _usage_text;
		policy_context.policy_name = _policy_name;
		policy_context.policy_usage = _policy_name + "_usage";
		policy_context.instance_name = _plugin_name;

		plugin_config = get_plugin_specific_configuration(_plugin_name);

		auto rule_engine_plugin = new plugin_type(policy_context.instance_name, "");

		rule_engine_plugin->add_operation<irods::default_re_ctx&, const std::string&>(
			"start", std::function<irods::error(irods::default_re_ctx&, const std::string&)>(start));

		rule_engine_plugin->add_operation<irods::default_re_ctx&, const std::string&>(
			"stop", std::function<irods::error(irods::default_re_ctx&, const std::string&)>(stop));

		rule_engine_plugin->add_operation<irods::default_re_ctx&, const std::string&, bool&>(
			"rule_exists", std::function<irods::error(irods::default_re_ctx&, const std::string&, bool&)>(rule_exists));

		rule_engine_plugin->add_operation<irods::default_re_ctx&, std::vector<std::string>&>(
			"list_rules", std::function<irods::error(irods::default_re_ctx&, std::vector<std::string>&)>(list_rules));

		rule_engine_plugin
			->add_operation<irods::default_re_ctx&, const std::string&, std::list<boost::any>&, irods::callback>(
				"exec_rule",
				std::function<irods::error(
					irods::default_re_ctx&, const std::string&, std::list<boost::any>&, irods::callback)>(exec_rule));

		rule_engine_plugin->add_operation<
			irods::default_re_ctx&,
			const std::string&,
			msParamArray_t*,
			const std::string&,
			irods::callback>(
			"exec_rule_text",
			std::function<irods::error(
				irods::default_re_ctx&, const std::string&, msParamArray_t*, const std::string&, irods::callback)>(
				exec_rule_text));

		rule_engine_plugin->add_operation<irods::default_re_ctx&, const std::string&, msParamArray_t*, irods::callback>(
			"exec_rule_expression",
			std::function<irods::error(irods::default_re_ctx&, const std::string&, msParamArray_t*, irods::callback)>(
				exec_rule_expression));

		return rule_engine_plugin;

	} // make

} // namespace irods::policy_composition::policy_engine

#endif // IRODS_POLICY_COMPOSITION_FRAMEWORK_POLICY_ENGINE_HPP
