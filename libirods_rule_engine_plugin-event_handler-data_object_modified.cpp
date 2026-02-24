#include <irods/policy_composition_framework_event_handler.hpp>

#include <irods/objDesc.hpp>
#include <irods/physPath.hpp>
#include <irods/bulkDataObjReg.h>

#include <fmt/format.h>

// Persistent L1 File Descriptor Table
extern l1desc_t L1desc[NUM_L1_DESC];

namespace
{
	// clang-format off
    using     json = nlohmann::json;
    namespace pc   = irods::policy_composition;
    namespace kw   = irods::policy_composition::keywords;
    namespace eh   = irods::policy_composition::event_handler;
	// clang-format on

	const std::map<std::string, std::string> p2e{
		{"bulk_data_obj_put", "CREATE"},
		{"data_obj_chksum", "CHECKSUM"},
		{"data_obj_copy", "COPY"},
		{"data_obj_create_and_stat", "CREATE"},
		{"data_obj_create", "CREATE"},
		{"data_obj_get", "GET"},
		{"data_obj_lseek", "SEEK"},
		{"data_obj_phymv", "REPLICATION"},
		{"data_obj_put", "PUT"},
		{"data_obj_rename", "RENAME"},
		{"data_obj_repl", "REPLICATION"},
		{"data_obj_trim", "TRIM"},
		{"data_obj_truncate", "TRUNCATE"},
		{"data_obj_unlink", "UNLINK"},
		{"phy_path_reg", "REGISTER"},
	};

	std::map<uint32_t, json> objects_in_flight{};

	std::string hierarchy_resolution_operation{};

	auto invoke_policy_for_bulk_put(
		ruleExecInfo_t* _rei,
		const std::string& _rule_name,
		genQueryOut_t& _attr_arr,
		keyValPair_t& _cond_input) -> void
	{
		const std::string event{hierarchy_resolution_operation};

		auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);

		auto data_name = getSqlResultByInx(&_attr_arr, COL_DATA_NAME);
		if (!data_name) {
			THROW(UNMATCHED_KEY_OR_INDEX, "missing object path");
		}

		auto offset = getSqlResultByInx(&_attr_arr, OFFSET_INX);
		if (!offset) {
			THROW(UNMATCHED_KEY_OR_INDEX, "missing offset");
		}

		std::vector<int> offset_int{};
		for (int i = 0; i < _attr_arr.rowCnt; ++i) {
			offset_int.push_back(atoi(&offset->value[offset->len * i]));
		}

		dataObjInp_t inp{};
		inp.condInput = _cond_input;
		for (int i = 0; i < _attr_arr.rowCnt; ++i) {
			rstrcpy(inp.objPath, &data_name->value[data_name->len * i], sizeof(inp.objPath));

			inp.dataSize = i == 0 ? offset_int[0] : offset_int[i] - offset_int[i - 1];

			auto obj = pc::serialize_dataObjInp_to_json(inp);

			obj[kw::policy_enforcement_point] = _rule_name;
			obj[kw::event] = event;
			obj[kw::comm] = comm;

			auto p2i = eh::configuration->plugin_configuration.at(kw::policies_to_invoke);
			auto stop = eh::configuration->plugin_configuration.contains("stop_on_error");

			pc::invoke_policies_for_event(_rei, stop, event, _rule_name, p2i, obj);

		} // for i

	} // invoke_policy_for_bulk_put

	auto hierarchy_handler(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> std::tuple<std::string, json>
	{
		auto it = pc::advance_or_throw(_arguments, 3);
		auto op = boost::any_cast<const std::string*>(*it);
		hierarchy_resolution_operation = *op;

		return std::make_tuple(eh::SKIP_POLICY_INVOCATION, json{});

	} // hierarchy_handler

	auto bulk_put_handler(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> std::tuple<std::string, json>
	{
		auto it = pc::advance_or_throw(_arguments, 2);

		auto inp = boost::any_cast<bulkOprInp_t*>(*it);
		invoke_policy_for_bulk_put(_rei, _rule_name, inp->attriArray, inp->condInput);

		return std::make_tuple(eh::SKIP_POLICY_INVOCATION, json{});

	} // bulk_put_handler

	auto copy_rename_handler(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> std::tuple<std::string, json>
	{
		auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);
		auto it = pc::advance_or_throw(_arguments, 2);

		const std::string event = pc::pep_to_event(p2e, _rule_name);

		auto inp = boost::any_cast<dataObjCopyInp_t*>(*it);

		auto p2i = eh::configuration->plugin_configuration.at(kw::policies_to_invoke);
		auto stop = eh::configuration->plugin_configuration.contains("stop_on_error");

		json src = pc::serialize_dataObjInp_to_json(inp->srcDataObjInp);
		src[kw::policy_enforcement_point] = _rule_name;
		src[kw::event] = event;
		src[kw::comm] = comm;
		pc::invoke_policies_for_event(_rei, stop, event, _rule_name, p2i, src);

		json dst = pc::serialize_dataObjInp_to_json(inp->destDataObjInp);
		dst[kw::policy_enforcement_point] = _rule_name;
		dst[kw::event] = event;
		dst[kw::comm] = comm;
		pc::invoke_policies_for_event(_rei, stop, event, _rule_name, p2i, dst);

		return std::make_tuple(eh::SKIP_POLICY_INVOCATION, json{});

	} // copy_rename_handler

	auto seek_handler(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> std::tuple<std::string, json>
	{
		auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);
		auto it = pc::advance_or_throw(_arguments, 2);

		auto inp = boost::any_cast<openedDataObjInp_t*>(*it);
		const auto l1_idx = inp->l1descInx;
		auto obj = objects_in_flight[l1_idx];
		if (obj.empty()) {
			return std::make_tuple(std::string{}, json{});
		}

		const std::string event = [&]() -> const std::string {
			const std::string& op = pc::pep_to_event(p2e, _rule_name);
			return op;
		}();

		obj[kw::policy_enforcement_point] = _rule_name;
		obj[kw::event] = event;
		obj[kw::comm] = comm;

		return std::make_tuple(event, obj);

	} // seek_handler

	// uses the file descriptor table to track modify operations
	// only add an entry if the object is created or opened for write
	auto create_open_handler(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> std::tuple<std::string, json>
	{
		auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);
		auto it = pc::advance_or_throw(_arguments, 2);
		auto inp = boost::any_cast<dataObjInp_t*>(*it);

		json obj{};
		try {
			int l1_idx{};
			std::tie(l1_idx, obj) = pc::get_index_and_json_from_obj_inp(inp);
			objects_in_flight[l1_idx] = obj;
		}
		catch (const irods::exception& _e) {
			pc::logger::debug("{}: irods::get_index_and_resource_from_obj_inp failed for [{}]", __func__, inp->objPath);
		}

		if (inp->openFlags & O_TRUNC) {
			obj[kw::event] = "TRUNCATE";
			return std::make_tuple(std::string{"TRUNCATE"}, obj);
		}

		return std::make_tuple(eh::SKIP_POLICY_INVOCATION, json{});

	} // create_open_handler

	// uses the tracked file descriptor table operations to invoke policy
	// if changes were actually made to the object
	auto close_handler(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> std::tuple<std::string, json>
	{
		auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);
		auto it = pc::advance_or_throw(_arguments, 2);

		uint32_t l1_idx{};
		if (_rule_name.find("replica_close") != std::string::npos) {
			auto bb = boost::any_cast<bytesBuf_t*>(*it);
			auto tmp = std::string{static_cast<char*>(bb->buf), static_cast<char*>(bb->buf) + bb->len};
			auto obj = json::parse(tmp);
			l1_idx = obj["fd"].get<uint32_t>();
		}
		else {
			const auto inp = boost::any_cast<openedDataObjInp_t*>(*it);
			l1_idx = inp->l1descInx;
		}

		auto obj = objects_in_flight[l1_idx];
		if (obj.empty()) {
			return std::make_tuple(std::string{}, json{});
		}

		auto open_flags = boost::lexical_cast<int>(obj["open_flags"].get<std::string>());
		auto write_flag = (open_flags & O_WRONLY || open_flags & O_RDWR);
		auto create_flag = (open_flags & O_CREAT);

		const auto event = [&]() -> const std::string {
			if ("CREATE" == hierarchy_resolution_operation)
				return "PUT";
			else if ("OPEN" == hierarchy_resolution_operation && write_flag)
				return "WRITE";
			else if ("OPEN" == hierarchy_resolution_operation && !write_flag)
				return "GET";
			else
				return hierarchy_resolution_operation;
		}();

		obj[kw::policy_enforcement_point] = _rule_name;
		obj[kw::event] = event;
		obj[kw::comm] = comm;

		return std::make_tuple(event, obj);

	} // close_handler

	auto data_obj_inp_handler(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> std::tuple<std::string, json>
	{
		auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);
		auto it = pc::advance_or_throw(_arguments, 2);

		auto inp = boost::any_cast<dataObjInp_t*>(*it);
		auto obj = pc::serialize_dataObjInp_to_json(*inp);

		const auto event = [&]() -> const std::string {
			std::string op = pc::pep_to_event(p2e, _rule_name);
			if (inp->oprType == UNREG_OPR) {
				return "UNREGISTER";
			}
			return op;
		}();

		obj[kw::policy_enforcement_point] = _rule_name;
		obj[kw::event] = event;
		obj[kw::comm] = comm;

		return std::make_tuple(event, obj);

	} // data_obj_inp_handler

} // namespace

extern "C" eh::plugin_pointer_type plugin_factory(const std::string& _pn, const std::string& _ctx)
{
	eh::register_handler("data_obj_put", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("data_obj_get", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("data_obj_unlink", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("data_obj_repl", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("phy_path_reg", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("data_obj_truncate", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("data_obj_trim", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("data_obj_chksum", eh::interfaces::api, data_obj_inp_handler);
	eh::register_handler("data_obj_create", eh::interfaces::api, create_open_handler);
	eh::register_handler("data_obj_open", eh::interfaces::api, create_open_handler);
	eh::register_handler("data_obj_close", eh::interfaces::api, close_handler);
	eh::register_handler("replica_open", eh::interfaces::api, create_open_handler);
	eh::register_handler("replica_close", eh::interfaces::api, close_handler);
	eh::register_handler("data_obj_lseek", eh::interfaces::api, seek_handler);
	eh::register_handler("data_obj_rename", eh::interfaces::api, copy_rename_handler);
	eh::register_handler("data_obj_copy", eh::interfaces::api, copy_rename_handler);
	eh::register_handler("bulk_data_obj_put", eh::interfaces::api, bulk_put_handler);

	eh::register_handler("resolve_hierarchy", eh::interfaces::resource, hierarchy_handler);

	return eh::make(_pn, _ctx);
} // plugin_factory
