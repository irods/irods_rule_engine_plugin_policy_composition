# irods_policy_engine_template
A basic template for an iRODS C++ Policy Engine

## Configuring the Data Object Modified Event Handler
```json
{
    "instance_name": "irods_rule_engine_plugin-event_handler_data_object_modified-instance",
    "plugin_name": "irods_rule_engine_plugin-event_handler_data_object_modified",
    "plugin_specific_configuration": {
        "policies_to_invoke": [
            {
                "pre_or_post_invocation": [
                    "post"
                ],
                "events": [
                    "create",
                    "read",
                    "write",
                    "rename",
                    "registration"
                ],
                "policy": "irods_policy_access_time",
                "configuration": {
                    "attribute": "irods::access_time"
                }
            }
        ]
    }
}
```
`pre_or_post_invocation` : Dictates when the policy should be invoked. A JSON array of either "PRE", "POST", or both.  Should not be left empty.
`events` : Events which would trigger the invocation of the configured policy.  A JSON array of all triggering events: "CREATE", "READ", "WRITE", "RENAME", or "REGISTRATION".  Should not be left empty.
`policy` : The name of the policy to invoke given the events and the pre or post configuration.  e.g. "irods_policy_access_time".  Should not be left empty.
`configuration` : A JSON object which is serialized into a string and passed to the policy.  May contain any policy-specific configuration.
