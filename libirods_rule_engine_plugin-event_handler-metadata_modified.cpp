#include <irods/modAVUMetadata.h>
#include <irods/rcConnect.h>

#undef IRODS_METADATA_ENABLE_SERVER_SIDE_API
#define IRODS_METADATA_ENABLE_SERVER_SIDE_API
#include <irods/metadata.hpp>

#include <irods/policy_composition_framework_event_handler.hpp>

namespace
{

	// clang-format off
    using     json = nlohmann::json;
    namespace pc   = irods::policy_composition;
    namespace xm   = irods::experimental::metadata;
    namespace kw   = irods::policy_composition::keywords;
    namespace eh   = irods::policy_composition::event_handler;
	// clang-format on

	auto metadata_modified(const std::string& _rule_name, const pc::arguments_type& _arguments, ruleExecInfo_t* _rei)
		-> eh::handler_return_type
	{
		const std::string event{"METADATA"};

		const std::map<xm::entity_type, std::string> to_variable{
			{xm::entity_type::collection, kw::logical_path},
			{xm::entity_type::data_object, kw::logical_path},
			{xm::entity_type::user, kw::user_name},
			{xm::entity_type::resource, kw::source_resource}};

		auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);

		auto it = _arguments.begin();
		std::advance(it, 2);
		if (_arguments.end() == it) {
			THROW(SYS_INVALID_INPUT_PARAM, "invalid number of arguments");
		}

		const auto inp{boost::any_cast<modAVUMetadataInp_t*>(*it)};
		const auto et{xm::to_entity_type(inp->arg1)};
		const auto var{to_variable.at(et)};

		json obj{};
		obj[kw::event] = event;
		obj[var] = inp->arg2;
		obj[kw::metadata] = {
			{kw::comm, comm},
			{kw::entity_type, xm::to_entity_string(et)},
			{kw::operation, inp->arg0},
			{kw::entity, inp->arg2},
			{kw::attribute, inp->arg3},
			{kw::value, inp->arg4},
			{kw::units, inp->arg5}};

		obj[kw::policy_enforcement_point] = _rule_name;

		return std::make_tuple(event, obj);

	} // metadata_modifehd

} // namespace

extern "C" eh::plugin_pointer_type plugin_factory(const std::string& _pn, const std::string& _ctx)
{
	eh::register_handler("mod_avu_metadata", eh::interfaces::api, metadata_modified);
	return eh::make(_pn, _ctx);
} // plugin_factory
