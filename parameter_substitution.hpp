#ifndef IRODS_POLICY_COMPOSITION_PARAMETER_SUBSTITUTION_HPP
#define IRODS_POLICY_COMPOSITION_PARAMETER_SUBSTITUTION_HPP

#include <irods/policy_composition_framework_logging_category.hpp>
#include <irods/irods_resource_manager.hpp>
#include <irods/irods_query.hpp>

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include <irods/filesystem.hpp>

#include <boost/lexical_cast.hpp>

#include <string>

extern irods::resource_manager resc_mgr;

namespace irods::policy_composition::policy_engine
{

	// clang-format off
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;
	// clang-format on

	namespace tokens
	{
		static const std::string query_substitution{"IRODS_TOKEN_QUERY_SUBSTITUTION_END_TOKEN"};
		static const std::string current_time{"IRODS_TOKEN_CURRENT_TIME_END_TOKEN"};
		static const std::string seconds_ago{"IRODS_TOKEN_SECONDS_AGO_END_TOKEN"};
		static const std::string user_name{"IRODS_TOKEN_USER_NAME_END_TOKEN"};
		static const std::string collection_name{"IRODS_TOKEN_COLLECTION_NAME_END_TOKEN"};
		static const std::string data_name{"IRODS_TOKEN_DATA_NAME_END_TOKEN"};
		static const std::string source_resource{"IRODS_TOKEN_SOURCE_RESOURCE_END_TOKEN"};
		static const std::string destination_resource{"IRODS_TOKEN_DESTINATION_RESOURCE_END_TOKEN"};
		static const std::string source_leaf_bundle{"IRODS_TOKEN_SOURCE_RESOURCE_LEAF_BUNDLE_END_TOKEN"};
		static const std::string destination_leaf_bundle{"IRODS_TOKEN_DESTINATION_RESOURCE_LEAF_BUNDLE_END_TOKEN"};
		static const std::string seconds_since_epoch{"IRODS_TOKEN_SECONDS_SINCE_EPOCH_END_TOKEN"};
		static std::map<std::string, uint32_t> index_map = {
			{current_time, 0},
			{seconds_ago, 1},
			{user_name, 2},
			{collection_name, 3},
			{data_name, 4},
			{source_resource, 5},
			{destination_resource, 6},
			{source_leaf_bundle, 5},
			{destination_leaf_bundle, 6},
			{seconds_since_epoch, 7}};
	}; //namespace tokens

	inline auto paramter_requires_query_substitution(const nlohmann::json& param) -> bool
	{
		if (param.is_string()) {
			return param.get<std::string>().find(tokens::query_substitution) != std::string::npos;
		}

		return false;

	} // paramter_requires_query_substitution

	inline auto split_logical_path(rsComm_t& comm, const std::string& lp) -> std::tuple<std::string, std::string>
	{
		fs::path p{lp};
		if (fsvr::is_data_object(comm, p)) {
			auto obj{p.object_name()};
			auto col{p.parent_path()};
			return std::make_tuple(obj, col);
		}
		else if (fsvr::is_collection(comm, p)) {
			return std::make_tuple("", lp);
		}

		return std::make_tuple("", "");

	} // split_logical_path

	inline auto compute_leaf_bundle(const std::string& resc_name)
	{
		std::string leaf_id_str;

		// if the resource has no children then simply return
		resource_ptr root_resc;
		error err = resc_mgr.resolve(resc_name, root_resc);
		if (!err.ok()) {
			logger::error("{}: Failed to compute leaf bundle for [{}]", __func__, resc_name);
			return std::string{};
		}

		std::vector<resource_manager::leaf_bundle_t> leaf_bundles = resc_mgr.gather_leaf_bundles_for_resc(resc_name);
		std::vector<std::string> quoted_ids;
		for (const auto& bundle : leaf_bundles) {
			std::transform(std::begin(bundle), std::end(bundle), std::back_inserter(quoted_ids), [](auto _id) {
				return fmt::format("'{}'", _id);
			});

		} // for
		leaf_id_str = fmt::format("{}", fmt::join(quoted_ids, ", "));

		// if there is no hierarchy
		if (leaf_id_str.empty()) {
			rodsLong_t resc_id;
			resc_mgr.hier_to_leaf_id(resc_name, resc_id);
			leaf_id_str = "'" + std::to_string(resc_id) + "'";
		}

		return leaf_id_str;

	} // compute_leaf_bundle

	//TODO :: possibly need to return an error
	inline void parse_and_replace_query_string_tokens(std::string& query_string, const std::vector<std::string>& values)
	{
		const std::string prefix{"IRODS_TOKEN_"};
		const std::string suffix{"_END_TOKEN"};
		std::string::size_type start{0};
		while (std::string::npos != start) {
			start = query_string.find(prefix, start);
			if (std::string::npos != start) {
				try {
					auto end = query_string.find(suffix, start + prefix.size());
					if (std::string::npos == end) {
						logger::error(
							"{}: Missing ending [{}] for query substitution [{}] at [{}]",
							__func__,
							suffix,
							query_string,
							start);
						return;
					}

					auto tok = query_string.substr(start, (end + suffix.size()) - start);
					auto val = values[tokens::index_map.at(tok)];

					std::string tmp{val};
					if (tokens::source_leaf_bundle == tok || tokens::destination_leaf_bundle == tok) {
						tmp = compute_leaf_bundle(val);
					}

					query_string.replace(start, tok.length(), tmp);

					start = end + suffix.size();
				}
				catch (const std::out_of_range& _e) {
					logger::error("{}: caught out of range for replace", __func__);
					return;
				}
			}
		}
	} // parse_and_replace_query_string_tokens

	template <typename T>
	auto perform_query_substitution(rsComm_t& comm, const nlohmann::json& param, const std::vector<std::string>& values)
		-> T
	{
		const auto delim = std::string{")"};
		auto str = param.get<std::string>();
		auto p0 = str.find(tokens::query_substitution);

		if (p0 == std::string::npos) {
			return T{};
		}

		p0 += tokens::query_substitution.size() + 1;

		auto p1 = str.find(delim, p0);
		if (p1 == std::string::npos) {
			return T{};
		}

		auto query = str.substr(p0, p1 - p0);

		parse_and_replace_query_string_tokens(query, values);

		irods::query<rsComm_t> qobj(&comm, query);

		if (qobj.size() > 0) {
			return boost::lexical_cast<T>(qobj.front()[0]);
		}

		return T{};

	} // perform_query_substitution

	inline void
	replace_query_string_token(std::string& query_string, const std::string& token, const std::string& value)
	{
		std::string tmp_val{value};
		if (tokens::source_leaf_bundle == token || tokens::destination_leaf_bundle == token) {
			tmp_val = compute_leaf_bundle(value);
		}

		std::string::size_type pos{0};
		while (std::string::npos != pos) {
			pos = query_string.find(token);
			if (std::string::npos != pos) {
				try {
					query_string.replace(pos, token.length(), tmp_val);
				}
				catch (const std::out_of_range& _e) {
				}
			}
		}
	} // replace_query_string_tokens

	template <typename T>
	void replace_query_string_token(std::string& query_string, const std::string token, T value)
	{
		auto value_string{std::to_string(value)};
		replace_query_string_token(query_string, token, value_string);
	} // replace_query_string_tokens

	inline void replace_positional_tokens(std::string& str, const std::vector<std::string>& results)
	{
		for (auto i = 0; i < results.size(); ++i) {
			std::string::size_type pos{0};
			std::string tok{"{" + std::to_string(i) + "}"};
			pos = str.find(tok, pos);
			while (std::string::npos != pos) {
				str.replace(pos, tok.size(), results[i]);
				pos = str.find(tok, pos);
			}
		}
	} // replace_positional_token

} // namespace irods::policy_composition::policy_engine

#endif // IRODS_POLICY_COMPOSITION_PARAMETER_SUBSTITUTION_HPP
