#ifndef IRODS_POLICY_COMPOSITION_FRAMEWORK_PARAMETER_CAPTURE_HPP
#define IRODS_POLICY_COMPOSITION_FRAMEWORK_PARAMETER_CAPTURE_HPP

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_hierarchy_parser.hpp>
#include <irods/irods_stacktrace.hpp>
#include <irods/rodsError.h>

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include <irods/filesystem.hpp>

#define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include <irods/irods_query.hpp>

#include <nlohmann/json.hpp>

namespace
{

	using json = nlohmann::json;

	template <typename T>
	T extract_object_parameter(const std::string& _name, const json& _params)
	{
		if (!_params.contains(_name)) {
			return T{};
		}

		return _params.at(_name);
	}

	struct TagFirstResc
	{
	} tag_first_resc;
	struct TagLastResc
	{
	} tag_last_resc;

	inline auto parse_hierarchy(const irods::hierarchy_parser& _p, TagFirstResc)
	{
		return _p.first_resc();
	}
	inline auto parse_hierarchy(const irods::hierarchy_parser& _p, TagLastResc)
	{
		return _p.last_resc();
	}

	template <typename TAG_TYPE>
	auto extract_dataobj_inp_parameters(const json& _params, TAG_TYPE T)
	{
		std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

		user_name = extract_object_parameter<std::string>("user_name", _params);

		auto comm_obj = json{};
		if (_params.contains("comm")) {
			comm_obj = _params.at("comm");
			if (user_name.empty()) {
				//user_name = extract_object_parameter<std::string>("proxy_user_name", comm_obj);
				user_name = extract_object_parameter<std::string>("user_user_name", comm_obj);
			}
		}

		logical_path = extract_object_parameter<std::string>("obj_path", _params);
		if (logical_path.empty()) {
			logical_path = extract_object_parameter<std::string>("logical_path", _params);
		}
		//if(logical_path.empty()) {
		//   logical_path = extract_object_parameter<std::string>("target", _params);
		//}

		source_resource = extract_object_parameter<std::string>("source_resource", _params);
		destination_resource = extract_object_parameter<std::string>("destination_resource", _params);

		if (_params.contains("cond_input")) {
			auto cond_input = _params.at("cond_input");
			if (source_resource.empty()) {
				source_resource = extract_object_parameter<std::string>("rescName", cond_input);
			}

			if (source_resource.empty()) {
				if (cond_input.contains("resc_hier")) {
					std::string resc_hier = cond_input.at("resc_hier");
					irods::hierarchy_parser parser(resc_hier);
					source_resource = parse_hierarchy(parser, T);
				}
			}

			if (destination_resource.empty()) {
				destination_resource = extract_object_parameter<std::string>("destRescName", cond_input);
				if (source_resource == destination_resource) {
					// e.g. if iput -R is used, which has no -S, the source & destination will be the same
					destination_resource.clear();
				}
			}

			if (destination_resource.empty()) {
				if (cond_input.contains("dest_resc_hier")) {
					std::string dest_resc_hier = cond_input.at("dest_resc_hier");
					irods::hierarchy_parser parser(dest_resc_hier);
					destination_resource = parse_hierarchy(parser, T);
				}
			}
		}

		return std::make_tuple(user_name, logical_path, source_resource, destination_resource);

	} //  extract_dataobj_inp_parameters

	template <typename T>
	T extract_array_parameter(json _params, size_t _idx)
	{
		return _params[_idx];
	}

	template <typename T, size_t... Is>
	auto extract_array_parameters_impl(json _params, std::index_sequence<Is...>)
	{
		return std::make_tuple(extract_array_parameter<T>(_params, Is)...);
	}

	template <size_t N, typename T>
	auto extract_array_parameters(json _params)
	{
		if (!_params.is_array()) {
			THROW(SYS_INVALID_INPUT_PARAM, "parameters is not a json array");
		}

		return extract_array_parameters_impl<T>(_params, std::make_index_sequence<N>{});

	} // extract_array_parameters

	inline auto
	get_metadata_for_resource(rsComm_t* _comm, const std::string& _meta_attr_name, const std::string& _resource_name)
	{
		std::string query_str{boost::str(
			boost::format("SELECT META_RESC_ATTR_VALUE, META_RESC_ATTR_UNITS WHERE META_RESC_ATTR_NAME = '%s' and "
		                  "RESC_NAME = '%s'") %
			_meta_attr_name % _resource_name)};
		irods::query<rsComm_t> qobj{_comm, query_str, 1};
		if (qobj.size() > 0) {
			return std::make_tuple(qobj.front()[0], qobj.front()[1]);
		}

		return std::make_tuple(std::string{}, std::string{});
	} // get_metadata_for_resource

	template <typename TAG_TYPE>
	auto capture_parameters(const json& params, TAG_TYPE T)
	{
		std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

		std::tie(user_name, logical_path, source_resource, destination_resource) =
			extract_dataobj_inp_parameters(params, T);

		if (params.contains("query_results")) {
			using fsp = irods::experimental::filesystem::path;

			std::string tmp_coll_name{}, tmp_data_name{};

			auto qr = params.at("query_results");

			if (qr.size() > 0 && user_name.empty()) {
				user_name = qr[0];
			}
			if (qr.size() > 1) {
				tmp_coll_name = qr[1];
			}
			if (qr.size() > 2) {
				tmp_data_name = qr[2];
			}
			if (qr.size() > 3 && source_resource.empty()) {
				source_resource = qr[3];
			}

			//if(logical_path.empty()) {
			if (!tmp_coll_name.empty() && !tmp_data_name.empty()) {
				logical_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
			}
		}

		return std::make_tuple(user_name, logical_path, source_resource, destination_resource);
	} // capture_parameters

} //namespace

#endif // IRODS_POLICY_COMPOSITION_FRAMEWORK_PARAMETER_CAPTURE_HPP
