
#include <irods/policy_composition_framework_policy_engine.hpp>
#include <irods/policy_composition_framework_parameter_capture.hpp>
#include <irods/policy_composition_framework_configuration_manager.hpp>

#include <irods/thread_pool.hpp>
#include <irods/query_processor.hpp>

#include <nlohmann/json.hpp>
#include <fmt/format.h>

#include "parameter_substitution.hpp"

namespace
{

	// clang-format off
    namespace pc   = irods::policy_composition;
    namespace kw   = irods::policy_composition::keywords;
    namespace pe   = irods::policy_composition::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;
	// clang-format on

	template <typename T>
	auto get(const json& j, const std::string& k, T d) -> T
	{
		if (!j.contains(k)) {
			return d;
		}

		return j.at(k).get<T>();
	} // get

	irods::error query_processor_policy(const pe::context& ctx, pe::arg_type out)
	{
		try {
			pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

			const auto& params = ctx.parameters;

			// clang-format off
            auto number_of_threads  = pc::get(params, "number_of_threads",  4);
            auto query_limit        = pc::get(params, "query_limit",        uint32_t{0});
            auto query_type_string  = pc::get(params, "query_type",         std::string{"general"});
            auto query_string       = pc::get(params, "query_string",       std::string{});
            auto policies_to_invoke = pc::get(params, "policies_to_invoke", json{});
            auto stop_on_error      = pc::get(params, "stop_on_error",      std::string{}) == "true";
			// clang-format on

			pe::client_message(
				{{"0.usage", fmt::format("{} requires query_string", ctx.policy_name)},
			     {"1.number_of_threads", number_of_threads},
			     {"2.query_limit", query_limit},
			     {"3.query_type", query_type_string},
			     {"4.query_string", query_string},
			     {"5.policies_to_invoke", policies_to_invoke.dump(4, ' ', false, json::error_handler_t::replace)},
			     {"6.stop_on_error", stop_on_error}});

			if (query_string.empty()) {
				return ERROR(SYS_INVALID_INPUT_PARAM, "irods_policy_query_processor - empty query string");
			}

			if (policies_to_invoke.empty()) {
				return ERROR(SYS_INVALID_INPUT_PARAM, "irods_policy_query_processor - empty policies_to_invoke");
			}

			if (ctx.parameters.contains("query_results")) {
				pe::replace_positional_tokens(
					query_string, ctx.parameters.at("query_results").get<std::vector<std::string>>());
			}

			std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};
			std::tie(user_name, logical_path, source_resource, destination_resource) =
				capture_parameters(ctx.parameters, tag_first_resc);

			auto& comm = *ctx.rei->rsComm;

			auto [data_name, coll_name] = pe::split_logical_path(comm, logical_path);

			std::vector<std::string> values = {
				std::to_string(std::time(nullptr)),
				"0",
				user_name,
				coll_name,
				data_name,
				source_resource,
				destination_resource,
				"0"};

			auto epoch_seconds_formatter{[](time_t _unix_epoch) { return fmt::format("{0:011}", _unix_epoch); }};

			time_t seconds_ago{};
			if (ctx.parameters.contains("seconds_ago")) {
				auto member_data = ctx.parameters["seconds_ago"];
				if (pe::paramter_requires_query_substitution(member_data)) {
					auto tmp = pe::perform_query_substitution<time_t>(comm, member_data, values);
					seconds_ago = std::time(nullptr) - tmp;
				}
				else {
					auto tmp = member_data.get<time_t>();
					seconds_ago = std::time(nullptr) - tmp;
				}
			}

			values[pe::tokens::index_map[pe::tokens::seconds_ago]] = epoch_seconds_formatter(seconds_ago);

			time_t seconds_since_epoch{};
			if (ctx.parameters.contains("seconds_since_epoch")) {
				auto member_data{ctx.parameters["seconds_since_epoch"]};
				if (pe::paramter_requires_query_substitution(member_data)) {
					seconds_since_epoch = pe::perform_query_substitution<time_t>(comm, member_data, values);
				}
				else {
					seconds_since_epoch = member_data.get<time_t>();
				}
			}

			values[pe::tokens::index_map[pe::tokens::seconds_since_epoch]] =
				epoch_seconds_formatter(seconds_since_epoch);

			pe::parse_and_replace_query_string_tokens(query_string, values);

			pe::client_message({{"0.message", fmt::format("{} query_string {}", ctx.policy_name, query_string)}});

			using json = nlohmann::json;
			using result_row = irods::query_processor<rsComm_t>::result_row;

			json params_to_pass{};
			if (ctx.parameters.contains(kw::parameters)) {
				params_to_pass = ctx.parameters.at(kw::parameters);
			}
			else {
				params_to_pass = ctx.parameters;
			}

			pe::client_message(
				{{"0.message",
			      fmt::format(
					  "{} params_to_pass {}",
					  ctx.policy_name,
					  params_to_pass.dump(4, ' ', false, json::error_handler_t::replace))}});

			auto job = [&](const result_row& _results) {
				// capture the row of results from the query
				auto res_arr = json::array();

				for (auto& r : _results) {
					res_arr.push_back(r);
				}

				std::list<boost::any> args;

				for (auto policy : policies_to_invoke) {
					json pam{}, cfg{};

					if (policy.contains(kw::parameters)) {
						pam = policy.at(kw::parameters);
						pam.insert(params_to_pass.begin(), params_to_pass.end());
					}
					else {
						pam = params_to_pass;
					}

					if (policy.contains(kw::configuration)) {
						cfg = policy.at(kw::configuration);
					}
					else if (ctx.parameters.contains(kw::configuration)) {
						cfg = ctx.parameters.at(kw::configuration);
					}

					// inject query results into parameters
					pam["query_results"] = res_arr;

					auto pnm = policy.at(kw::policy_to_invoke).get<std::string>();

					std::string params{pam.dump(-1, ' ', false, json::error_handler_t::replace)};
					std::string config{cfg.dump(-1, ' ', false, json::error_handler_t::replace)};
					std::string out{};

					args.clear();
					args.push_back(boost::any(&params));
					args.push_back(boost::any(&config));
					args.push_back(boost::any(&out));

					pc::invoke_policy(ctx.rei, pnm, args);

					if (stop_on_error && out.size() > 0 && pc::contains_error(out)) {
						freeRErrorContent(&ctx.rei->rsComm->rError);
						break;
					}

				} // for policy
			}; // job

			auto query_type = irods::query<rsComm_t>::convert_string_to_query_type(query_type_string);

			auto tp = irods::thread_pool{number_of_threads};
			auto qp = irods::query_processor<rsComm_t>{query_string, job, query_limit, query_type};
			auto f = qp.execute(tp, *ctx.rei->rsComm);
			auto errors = f.get();

			if (errors.size() > 0) {
				for (auto& e : errors) {
					pc::logger::error("{}: query failed [{}]::[{}]", __func__, std::get<0>(e), std::get<1>(e));
				}

				return ERROR(
					SYS_INVALID_OPR_TYPE,
					boost::format("query processor encountered an error for [%d] rows for query [%s]") % errors.size() %
						query_string.c_str());
			}

			if (0 == f.size() && ctx.parameters.contains("default_results_when_no_rows_found")) {
				auto default_results = ctx.parameters.at("default_results_when_no_rows_found");

				result_row res;
				for (auto& row : default_results) {
					res.clear();
					for (auto& r : row) {
						res.push_back(r.get<std::string>());
					}

					job(res);
				}
			}
		}
		catch (const irods::exception& e) {
			if (CAT_NO_ROWS_FOUND == e.code()) {
				return SUCCESS();
			}
			else {
				pc::exception_to_rerror(e, ctx.rei->rsComm->rError);
				return ERROR(e.code(), e.what());
			}
		}

		return SUCCESS();

	} // query_processor_policy

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": ""
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
	return pe::make(_plugin_name, "irods_policy_query_processor", usage, query_processor_policy);
} // plugin_factory
