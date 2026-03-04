#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_EVENT_HANDLER_HPP
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_EVENT_HANDLER_HPP

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>

#include "policy_composition_framework_utilities.hpp"
#include "policy_composition_framework_plugin_configuration_json.hpp"

#include "boost/any.hpp"
#include "boost/lexical_cast.hpp"

namespace irods::policy_composition::event_handler
{

	// clang-format off
    namespace ipc = irods::policy_composition;

    using json                = nlohmann::json;
    using handler_return_type = std::tuple<std::string, json>;
    using handler_type        = handler_return_type (*)(const std::string&, const ipc::arguments_type&, ruleExecInfo_t*);
    using handler_map_type    = std::map<std::string, handler_type>;
    using configuration_type  = std::unique_ptr<irods::plugin_configuration_json>;
    using consumed_pep_type   = std::set<std::string>;
    using plugin_type         = pluggable_rule_engine<irods::default_re_ctx>;
    using plugin_pointer_type = plugin_type*;
	// clang-format on

	handler_map_type handlers{};
	configuration_type configuration{};
	consumed_pep_type consumed_policy_enforcement_points{};
	std::string plugin_instance_name{};

	const std::string SKIP_POLICY_INVOCATION{"skip_policy_invocation"};

	namespace policy_clauses
	{
		const std::string pre{"pre"};
		const std::string post{"post"};
		const std::string except{"except"};
		const std::string finally{"finally"};
	} //namespace policy_clauses

	namespace interfaces
	{
		const std::string api{"api"};
		const std::string auth{"auth"};
		const std::string database{"database"};
		const std::string network{"network"};
		const std::string resource{"resource"};
	} // namespace interfaces

	inline auto register_handler(const std::string& _operation, const std::string& _interface, handler_type _handler) -> void
	{
		const std::string prefix{"pep"}, sep{"_"};
		const std::string stem{prefix + sep + _interface + sep + _operation + sep};

		auto k0 = stem + policy_clauses::pre;
		consumed_policy_enforcement_points.insert(k0);
		handlers[k0] = _handler;

		auto k1 = stem + policy_clauses::post;
		consumed_policy_enforcement_points.insert(k1);
		handlers[k1] = _handler;

		auto k2 = stem + policy_clauses::except;
		consumed_policy_enforcement_points.insert(k2);
		handlers[k2] = _handler;

		auto k3 = stem + policy_clauses::finally;
		consumed_policy_enforcement_points.insert(k3);
		handlers[k3] = _handler;

	} // register handler

	inline auto rule_name_is_supported(const std::string& _rule_name)
	{
		return (consumed_policy_enforcement_points.find(_rule_name) != consumed_policy_enforcement_points.end());
	} // rule_name_is_supported

	inline void
	process_policy_enforcement_point(const std::string& _pep, ruleExecInfo_t* _rei, const std::list<boost::any>& _args)
	{
		if (handlers.find(_pep) != handlers.end()) {
			auto hdlr = handlers.at(_pep);

			auto [event, obj] = hdlr(_pep, _args, _rei);

			if (!event.empty() && !obj.empty()) {
				auto p2i = configuration->plugin_configuration.at("policies_to_invoke");
				auto stop = configuration->plugin_configuration.contains("stop_on_error");
				ipc::invoke_policies_for_event(_rei, stop, event, _pep, p2i, obj);
			}
		}

	} // process_policy_enforcement_point

	namespace
	{
		irods::error start(irods::default_re_ctx&, const std::string& _instance_name)
		{
			// capture plugin instance name
			plugin_instance_name = _instance_name;

			// load the plugin specific configuration for this instance
			configuration = std::make_unique<irods::plugin_configuration_json>(plugin_instance_name);

#if 0
            // build a list of pep strings for the regexp
            std::string regex{};
            for( auto& s : consumed_policy_enforcement_points) {
                regex += s + " || ";
            }

            // trim trailing " || "
            regex = regex.substr(0, regex.size()-4);

            // register the event handler's peps as implemented by this plugin
            RuleExistsHelper::Instance()->registerRuleRegex(regex);
#endif
			RuleExistsHelper::Instance()->registerRuleRegex("pep_.*");

			return SUCCESS();
		}

		irods::error stop(irods::default_re_ctx&, const std::string&)
		{
			return SUCCESS();
		}

		irods::error rule_exists(irods::default_re_ctx&, const std::string& _rule_name, bool& _return_value)
		{
			_return_value = rule_name_is_supported(_rule_name);
			return SUCCESS();
		}

		irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules)
		{
			for (auto& s : consumed_policy_enforcement_points) {
				_rules.push_back(s);
			}
			return SUCCESS();
		}

		irods::error exec_rule(
			irods::default_re_ctx&,
			const std::string& _rule_name,
			std::list<boost::any>& _arguments,
			irods::callback _eff_hdlr)
		{
			ruleExecInfo_t* rei{};

			// capture an rei which provides the rsComm_t structure and rError
			const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);
			if (!err.ok()) {
				// always return SYS_NOT_SUPPORTED given an error in an Event Handler
				// which allows the REPF to continue trying other plugins or rule bases
				return ERROR(SYS_NOT_SUPPORTED, err.result());
			}

			try {
				// given a specific PEP, invoke the event handler
				process_policy_enforcement_point(_rule_name, rei, _arguments);
			}
			catch (const std::invalid_argument& _e) {
				// pass the exception to the rError stack to get the result
				// back to the client for forensics
				ipc::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const boost::bad_lexical_cast& _e) {
				ipc::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const boost::bad_any_cast& _e) {
				ipc::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const irods::exception& _e) {
				ipc::exception_to_rerror(_e, rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const std::exception& _e) {
				ipc::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			catch (const nlohmann::json::exception& _e) {
				ipc::exception_to_rerror(SYS_NOT_SUPPORTED, _e.what(), rei->rsComm->rError);
				return ERROR(SYS_NOT_SUPPORTED, _e.what());
			}
			// this code signals to the REPF that we were successfull but should continue
			// looking for further implementations of the same policy enforcement point
			return CODE(RULE_ENGINE_CONTINUE);

		} // exec_rule

		irods::error
		exec_rule_text(irods::default_re_ctx&, const std::string&, msParamArray_t*, const std::string&, irods::callback)
		{
			return ERROR(RULE_ENGINE_CONTINUE, "exec_rule_text is not supported");
		} // exec_rule_text

		irods::error exec_rule_expression(irods::default_re_ctx&, const std::string&, msParamArray_t*, irods::callback)
		{
			return ERROR(RULE_ENGINE_CONTINUE, "exec_rule_expression is not supported");
		} // exec_rule_expression

	} // namespace

	inline plugin_pointer_type make(const std::string& _plugin_name, const std::string& _context)
	{
		auto rule_engine_plugin = new plugin_type(_plugin_name, "");

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

} //namespace irods::policy_composition::event_handler

#endif // IRODS_POLICY_COMPOSITION_FRAMEWORK_EVENT_HANDLER_HPP
