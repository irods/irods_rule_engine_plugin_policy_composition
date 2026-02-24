#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_UTILITIES_HPP
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_UTILITIES_HPP

#include "policy_composition_framework_keywords.hpp"
#include <irods/policy_composition_framework_logging_category.hpp>

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_at_scope_exit.hpp>

#include <irods/rodsError.h>
#include <irods/generalAdmin.h>

#include <nlohmann/json.hpp>

#include <string>
#include <map>

namespace irods::policy_composition
{

	// clang-format off
    using json           = nlohmann::json;
    using event_map_type = std::map<std::string, std::string>;
    using arguments_type = std::list<boost::any>;
	// clang-format on

	template <typename T>
	auto get(const json& j, const std::string& k, T d) -> T
	{
		if (!j.contains(k)) {
			return d;
		}

		return j.at(k).get<T>();
	} // get

	template <typename Function>
	int exec_as_user(rsComm_t& _comm, const std::string& _user_name, Function _func)
	{
		if (_user_name.empty()) {
			THROW(SYS_INVALID_INPUT_PARAM, "user name is empty");
		}

		auto& user = _comm.clientUser;

		const auto old_user_name = std::string{user.userName};

		rstrcpy(user.userName, _user_name.data(), NAME_LEN);

		irods::at_scope_exit<std::function<void()>> at_scope_exit{
			[&user, &old_user_name] { rstrcpy(user.userName, old_user_name.c_str(), MAX_NAME_LEN); }};

		return _func(_comm);

	} // exec_as_user

	std::string demangle(const char* name);

	auto any_to_string(boost::any&);
	auto error_to_json(const irods::error&) -> json;
	auto contains_error(const std::string&) -> bool;
	void json_to_rerror(const json&, rError_t&);
	void exception_to_rerror(const irods::exception&, rError_t&);
	void exception_to_rerror(const int, const char*, rError_t&);
	auto collapse_error_stack(rError_t& _error);
	void invoke_policy(ruleExecInfo_t*, const std::string&, std::list<boost::any>&);

	auto advance_or_throw(const arguments_type&, const uint32_t) -> arguments_type::const_iterator;
	auto pep_to_event(const event_map_type&, const std::string&) -> std::string;
	auto get_index_and_json_from_obj_inp(const dataObjInp_t*) -> std::tuple<int, json>;
	auto serialize_generalAdminInp_to_json(const generalAdminInp_t&) -> json;
	auto serialize_keyValPair_to_json(const keyValPair_t&) -> json;
	auto serialize_collInp_to_json(const collInp_t&) -> json;
	auto serialize_dataObjInp_to_json(const dataObjInp_t&) -> json;
	auto serialize_openedDataObjInp_to_json(const openedDataObjInp_t& _inp) -> json;
	auto serialize_rsComm_to_json(rsComm_t*) -> json;
	auto invoke_policies_for_event(
		ruleExecInfo_t*,
		const bool,
		const std::string&,
		const std::string&,
		const json&,
		const json&) -> void;

} // namespace irods::policy_composition

#endif // IRODS_POLICY_COMPOSITION_FRAMEWORK_UTILITIES_HPP
