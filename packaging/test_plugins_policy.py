import os
import sys
import time
import contextlib
import tempfile
import shutil

import os.path

from time import sleep

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from ..configuration import IrodsConfig
from ..controller import IrodsController
from .resource_suite import ResourceBase

from . import session
from .. import paths
from .. import lib


class TestPolicyEngineVerifyChecksum(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineVerifyChecksum, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineVerifyChecksum, self).tearDown()

    @contextlib.contextmanager
    def filesystem_usage_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-verify_checksum-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-verify_checksum",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    def test_verify_checksum_success(self):
        with session.make_session_for_existing_admin() as admin_session:
            value = ""

            try:
                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke"    : "irods_policy_verify_checksum",
        "parameters" : {
            "logical_path" : "/tempZone/home/rods/file0",
            "source_resource" : "demoResc"
        }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                admin_session.assert_icommand(['iput', '-fK', rule_file, 'file0'])

                out = 'need more scope'
                with self.filesystem_usage_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')

            finally:
                admin_session.assert_icommand('irm -f ' + 'file0')
                print('annnnd... were done\n')


    def test_verify_checksum_failure(self):
        with session.make_session_for_existing_admin() as admin_session:
            value = ""

            try:
                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke"    : "irods_policy_verify_checksum",
        "parameters" : {
            "logical_path" : "/tempZone/home/rods/file0",
            "source_resource" : "demoResc"
        }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                admin_session.assert_icommand(['iput', '-fK', rule_file, 'file0'])

                with open('/var/lib/irods/Vault/home/rods/file0', 'w') as f:
                    f.write('X')

                out = 'need more scope'
                with self.filesystem_usage_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')

            finally:
                admin_session.assert_icommand('irm -f ' + 'file0')
                print('annnnd... were done\n')

class TestPolicyEngineQueryProcessor(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineQueryProcessor, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineQueryProcessor, self).tearDown()

    @contextlib.contextmanager
    def query_processor_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_verification-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_verification",
                    "plugin_specific_configuration": {
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    def test_query_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                # verification which fails on a replica existing on AnotherResc
                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "stop_on_error" : "true",
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "parameters" : {
                          "source_resource" : "AnotherResc"
                      },
                      "configuration" : {
                      }
                  },
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_seconds_ago(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.query_processor_configured():
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                    sleep(10)
                    rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "seconds_ago" : 5,
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND DATA_ACCESS_TIME < 'IRODS_TOKEN_SECONDS_AGO_END_TOKEN'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                    rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                    with open(rule_file, 'w') as f:
                        f.write(rule)

                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_seconds_ago_with_substitution(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.query_processor_configured():
                    admin_session.assert_icommand('imeta set -R demoResc irods::testing::time 4')
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                    sleep(10)
                    rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "source_resource" : "demoResc",
              "seconds_ago" : "IRODS_TOKEN_QUERY_SUBSTITUTION_END_TOKEN(SELECT META_RESC_ATTR_VALUE WHERE META_RESC_ATTR_NAME = 'irods::testing::time' AND RESC_NAME = 'IRODS_TOKEN_SOURCE_RESOURCE_END_TOKEN')",
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND DATA_ACCESS_TIME < 'IRODS_TOKEN_SECONDS_AGO_END_TOKEN'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                    rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                    with open(rule_file, 'w') as f:
                        f.write(rule)

                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('imeta rm -R demoResc irods::testing::time 4')
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_seconds_since_epoch(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.query_processor_configured():
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                    sleep(10)
                    rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "seconds_since_epoch" : 5,
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND DATA_ACCESS_TIME > 'IRODS_TOKEN_SECONDS_SINCE_EPOCH_END_TOKEN'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                    rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                    with open(rule_file, 'w') as f:
                        f.write(rule)

                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_seconds_since_epoch_with_substitution(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.query_processor_configured():
                    admin_session.assert_icommand('imeta set -R demoResc irods::testing::time 4')
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                    sleep(10)
                    rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "source_resource" : "demoResc",
              "seconds_since_epoch" : "IRODS_TOKEN_QUERY_SUBSTITUTION_END_TOKEN(SELECT DATA_ACCESS_TIME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file')",
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND DATA_ACCESS_TIME = 'IRODS_TOKEN_SECONDS_SINCE_EPOCH_END_TOKEN'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                    rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                    with open(rule_file, 'w') as f:
                        f.write(rule)

                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('imeta rm -R demoResc irods::testing::time 4')
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_with_default(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'incorrect_file_name'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "default_results_when_no_rows_found" : [["rods", "/tempZone/home/rods", "test_put_file", "demoResc"]],
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')


    def test_query_to_query_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
            "query_string" : "SELECT COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
            "query_limit" : 1,
            "query_type" : "general",
            "number_of_threads" : 1,
            "policies_to_invoke" : [
                {
                    "policy_to_invoke" : "irods_policy_query_processor",
                    "parameters" : {
                        "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '{0}' AND DATA_NAME = '{1}'",
                        "query_limit" : 1,
                        "query_type" : "general",
                        "number_of_threads" : 1,
                        "policies_to_invoke" : [
                            {
                                "policy_to_invoke" : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

class TestEventHandlerObjectModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerObjectModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerObjectModified, self).tearDown()

    @contextlib.contextmanager
    def event_handler_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "logical_path" : "\\/tempZone.*"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read", "write", "rename", "register", "unregister", "replication", "checksum", "copy", "seek", "truncate", "open", "close"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_fail_policy_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    'plugin_specific_configuration': {
                        "stop_on_error" : "true",
                        "policies_to_invoke" : [
                            {
                                "active_policy_clauses" : ["post"],
                                "events" : ["put"],
                                "policy_to_invoke" : "irods_policy_data_verification",
                                "parameters" : {
                                    "source_resource" : "demoResc",
                                    "destination_resource" : "AnotherResc"
                                },
                                "configuration" : {
                                }
                            },
                            {
                                "conditional" : {
                                    "logical_path" : "\\/tempZone.*"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["put"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_verification-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_verification",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_configured_fail_conditional(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "logical_path" : "\\/badZone.*"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read", "write", "rename", "register", "unregister", "replication", "checksum", "copy", "seek", "truncate"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_recurisve_collection_metadata_exists(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {

                                    "logical_path" : "\\/tempZone.*",

                                    "metadata_exists" : {
                                        "recursive"   : "true",
                                        "entity_type" : "collection",
                                        "attribute"   : "test_attribute",
                                        "value"       : "test_value",
                                        "units"       : "test_units",
                                    }
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read",
                                            "write", "rename", "register", "unregister",
                                            "replication", "checksum", "copy", "seek",
                                            "truncate", "open", "close"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_user_metadata_exists(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {

                                    "logical_path" : "\\/tempZone.*",

                                    "metadata_exists" : {
                                        "entity_type" : "user",
                                        "attribute"   : "test_attribute",
                                        "value"       : "test_value",
                                        "units"       : "test_units",
                                    }
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read",
                                            "write", "rename", "register", "unregister",
                                            "replication", "checksum", "copy", "seek",
                                            "truncate", "open", "close"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_resource_metadata_exists(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {

                                    "logical_path" : "\\/tempZone.*",

                                    "metadata_exists" : {
                                        "entity_type" : "resource",
                                        "attribute"   : "test_attribute",
                                        "value"       : "test_value",
                                        "units"       : "test_units",
                                    }
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read",
                                            "write", "rename", "register", "unregister",
                                            "replication", "checksum", "copy", "seek",
                                            "truncate", "open", "close"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    def test_event_handler_put_resource_metadata_exists(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_resource_metadata_exists():
                try:
                    admin_session.assert_icommand('imeta set -R demoResc test_attribute test_value test_units')

                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -f ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'PUT')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)
                    admin_session.assert_icommand('imeta rm -R demoResc test_attribute test_value test_units')

    def test_event_handler_put_resource_metadata_exists_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_resource_metadata_exists():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -f ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)

    def test_event_handler_put_user_metadata_exists(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_user_metadata_exists():
                try:
                    admin_session.assert_icommand('imeta set -u rods test_attribute test_value test_units')

                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -f ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'PUT')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)
                    admin_session.assert_icommand('imeta rm -u rods test_attribute test_value test_units')

    def test_event_handler_put_user_metadata_exists_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_user_metadata_exists():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -f ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)

    def test_event_handler_put_recursive_metadata_exists_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_recurisve_collection_metadata_exists():
                try:
                    coll_name = 'test_collection_metadata'
                    admin_session.assert_icommand('imkdir ' + coll_name)
                    admin_session.assert_icommand('imeta add -C ' + coll_name + ' test_attribute_fail test_value_fail test_units_fail')

                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename + ' ' + coll_name)
                    admin_session.assert_icommand('imeta ls -d ' + coll_name + '/' + filename, 'STDOUT_SINGLELINE', 'None')
                finally:
                    admin_session.assert_icommand('irm -rf ' + coll_name)

    def test_event_handler_put(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'PUT')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)

    def test_event_handler_put_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_fail_policy_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_put_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_configured_fail_conditional():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)

    def test_event_handler_get(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand('iget -f ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'GET')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_istream_put(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_configured():
                try:
                    filename = 'test_put_file'
                    contents = 'hello, world!'
                    admin_session.assert_icommand(['istream', 'write', filename], input=contents)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'PUT')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_istream_get(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand(['istream', 'write', filename], input=contents)
            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand(['istream', 'read', filename], 'STDOUT', [contents])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'GET')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_mv(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename  = 'test_put_file'
            filename2 = 'test_put_file2'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand('imv ' + filename + ' ' + filename2)
                    #admin_session.assert_icommand('imeta ls -d /tempZone/home/rods', 'STDOUT_SINGLELINE', 'RENAME')
                    admin_session.assert_icommand('imeta ls -d ' + filename2, 'STDOUT_SINGLELINE', 'RENAME')
                finally:
                    admin_session.assert_icommand('imeta rm -C /tempZone/home/rods irods_policy_testing_policy RENAME')
                    admin_session.assert_icommand('irm -f ' + filename2)


    def test_event_handler_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename  = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand('ichksum ' + filename, 'STDOUT_SINGLELINE', filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'CHECKSUM')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_copy(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename  = 'test_put_file'
            filename2 = 'test_put_file2'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand('icp ' + filename + ' ' + filename2)
                    admin_session.assert_icommand('imeta ls -d ' + filename,  'STDOUT_SINGLELINE', 'COPY')
                    admin_session.assert_icommand('imeta ls -d ' + filename2, 'STDOUT_SINGLELINE', 'COPY')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)
                    admin_session.assert_icommand('irm -f ' + filename2)


    def test_event_handler_istream_seek(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand(['istream', 'write', filename], input=contents)
            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand(['istream', '--offset', '1', 'write', filename], input=contents)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'SEEK')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_istream_truncate(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand(['istream', 'write', filename], input=contents)
            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand(['istream', '--offset', '1', 'write', filename], input=contents)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'TRUNCATE')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_register(self):
        with session.make_session_for_existing_admin() as admin_session:
            physical_path = '/tmp/test_event_handler_register'
            lib.create_local_testfile(physical_path)

            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand('ireg ' + physical_path + ' /tempZone/home/rods/regfile')
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', 'rods')
                    admin_session.assert_icommand('imeta ls -d /tempZone/home/rods/regfile', 'STDOUT_SINGLELINE', 'REGISTER')
                finally:
                    admin_session.assert_icommand('irm -f /tempZone/home/rods/regfile')


    def test_event_handler_unregister(self):
        with session.make_session_for_existing_admin() as admin_session:
            physical_path = '/tmp/test_event_handler_unregister'
            lib.create_local_testfile(physical_path)

            with self.event_handler_configured():
                try:
                    admin_session.assert_icommand('ireg ' + physical_path + ' /tempZone/home/rods/regfile')
                    admin_session.assert_icommand('iunreg /tempZone/home/rods/regfile')
                    admin_session.assert_icommand('imeta ls -C /tempZone/home/rods', 'STDOUT_SINGLELINE', 'UNREGISTER')
                finally:
                    admin_session.assert_icommand('imeta rm -C /tempZone/home/rods irods_policy_testing_policy UNREGISTER')

class TestEventHandlerCollectionModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerCollectionModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerCollectionModified, self).tearDown()

    @contextlib.contextmanager
    def event_handler_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-collection_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-collection_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "logical_path" : "\\/tempZone.*"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["create", "register", "remove"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )



        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_configured_fail_conditional(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-collection_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-collection_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "logical_path" : "\\/badZone.*"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["create", "register", "remove"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    def test_event_handler_collection_mkdir(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.event_handler_configured():
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('imkdir ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C ' + collection_name, 'STDOUT_SINGLELINE', 'CREATE')
            finally:
                admin_session.assert_icommand('irm -rf ' + collection_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_collection_mkdir_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.event_handler_configured_fail_conditional():
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('imkdir ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C ' + collection_name, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('irm -rf ' + collection_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_collection_rmdir(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.event_handler_configured():
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('imkdir ' + collection_name)
                    admin_session.assert_icommand('irmdir -f ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C /tempZone/home/rods', 'STDOUT_SINGLELINE', 'REMOVE')
            finally:
                admin_session.assert_icommand('imeta rm -C /tempZone/home/rods irods_policy_testing_policy REMOVE')
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_collection_register(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.event_handler_configured():
                    local_dir = '/tmp/test_event_handler_collection_register_dir'
                    if not os.path.isdir(local_dir):
                        lib.make_large_local_tmp_dir(local_dir, 10, 100)
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('ireg -r ' + local_dir + ' ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C ' + collection_name, 'STDOUT_SINGLELINE', 'REGISTER')
            finally:
                shutil.rmtree(local_dir)
                admin_session.assert_icommand('irm -rf ' + collection_name)
                admin_session.assert_icommand('iadmin rum')

class TestEventHandlerMetadataModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerMetadataModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerMetadataModified, self).tearDown()

    @contextlib.contextmanager
    def event_handler_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-metadata_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-metadata_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "active_policy_clauses" : ["post"],
                                "events" : ["metadata"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()


    def test_event_handler_object(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.event_handler_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta add -d ' + filename + ' attribute value unit')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'METADATA')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_collection(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('imeta add -C /tempZone/home/rods attribute value unit')
                    admin_session.assert_icommand('imeta ls -C /tempZone/home/rods', 'STDOUT_SINGLELINE', 'METADATA')
            finally:
                admin_session.assert_icommand('imeta rm -C /tempZone/home/rods attribute value unit')
                admin_session.assert_icommand('imeta rm -C /tempZone/home/rods irods_policy_testing_policy METADATA')


    def test_event_handler_user(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('imeta add -u rods attribute value unit')
                    admin_session.assert_icommand('imeta ls -u rods', 'STDOUT_SINGLELINE', 'METADATA')
            finally:
                admin_session.assert_icommand('imeta rm -u rods attribute value unit')
                admin_session.assert_icommand('imeta rm -u rods irods_policy_testing_policy METADATA')


    def test_event_handler_resource(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('imeta add -R demoResc attribute value unit')
                    admin_session.assert_icommand('imeta ls -R demoResc', 'STDOUT_SINGLELINE', 'METADATA')
            finally:
                admin_session.assert_icommand('imeta rm -R demoResc attribute value unit')
                admin_session.assert_icommand('imeta rm -R demoResc irods_policy_testing_policy METADATA')

class TestPolicyEngineFilesystemUsage(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineFilesystemUsage, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineFilesystemUsage, self).tearDown()

    @contextlib.contextmanager
    def filesystem_usage_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-filesystem_usage-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-filesystem_usage",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    def test_filesystem_usage(self):
        with session.make_session_for_existing_admin() as admin_session:
            value = ""

            try:
                rule = """
{
    "policy_to_invoke" : "irods_policy_enqueue_rule",
    "parameters" : {
        "comment"          : "Set the PLUSET value to the interval desired to run the rule",
        "delay_conditions" : "<PLUSET>10s</PLUSET><EF>REPEAT FOR EVER</EF><INST_NAME>irods_rule_engine_plugin-cpp_default_policy-instance</INST_NAME>",
        "policy_to_invoke" : "irods_policy_execute_rule",
        "parameters" : {
            "policy_to_invoke"    : "irods_policy_filesystem_usage",
            "parameters" : {
                "source_resource" : "demoResc"
            }
        }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                out = 'need more scope'
                with self.filesystem_usage_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    done = False;
                    while(not done):
                        command_to_execute = ['iquest', '%s', "SELECT META_RESC_ATTR_VALUE WHERE RESC_NAME = 'demoResc' AND META_RESC_ATTR_NAME = 'irods::resource::filesystem_percent_used'"]
                        out, err, ec = admin_session.run_icommand(command_to_execute)
                        lib.log_command_result(command_to_execute, out, err, ec)
                        if(out.find('CAT_NO_ROWS_FOUND') == -1):
                            done = True
                        else:
                            time.sleep(0.5)
                            done = False

                assert(out != '')

            finally:
                admin_session.assert_icommand('iqdel -a')

                # Run 'command_to_execute' again to update 'out' since the value in the attribute
                # 'irods::resource::filesystem_percent_used' may have been updated before the delay rules were cleared.
                out, err, ec = admin_session.run_icommand(command_to_execute)
                lib.log_command_result(command_to_execute, out, err, ec)

                admin_session.assert_icommand('imeta rm -R demoResc irods::resource::filesystem_percent_used '+out)

class TestPolicyEngineDataRetention(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineDataRetention, self).setUp()
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand("iadmin mkresc rnd random", 'STDOUT_SINGLELINE', 'random')
            admin_session.assert_icommand("iadmin mkresc ufs0 'unixfilesystem' localhost:/tmp/irods/ufs0", 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand("iadmin mkresc ufs1 'unixfilesystem' localhost:/tmp/irods/ufs1", 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand("iadmin mkresc ufs2 'unixfilesystem' localhost:/tmp/irods/ufs2", 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand("iadmin addchildtoresc rnd ufs0")
            admin_session.assert_icommand("iadmin addchildtoresc rnd ufs1")
            admin_session.assert_icommand("iadmin addchildtoresc rnd ufs2")
    def tearDown(self):
        super(TestPolicyEngineDataRetention, self).tearDown()
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand("iadmin rmchildfromresc rnd ufs0")
            admin_session.assert_icommand("iadmin rmchildfromresc rnd ufs1")
            admin_session.assert_icommand("iadmin rmchildfromresc rnd ufs2")
            admin_session.assert_icommand("iadmin rmresc ufs0")
            admin_session.assert_icommand("iadmin rmresc ufs1")
            admin_session.assert_icommand("iadmin rmresc ufs2")
            admin_session.assert_icommand("iadmin rmresc rnd")

    @contextlib.contextmanager
    def data_retention_remove_all_direct_invocation_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                    "plugin_specific_configuration": {
                        "log_errors" : "true",
                        "mode" : "remove_all_replicas"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_retention_trim_single_direct_invocation_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_retention_alternate_attributes_direct_invocation_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                    "plugin_specific_configuration": {
                        "log_errors" : "true",
                        "mode" : "trim_single_replica"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()



    ###############




    @contextlib.contextmanager
    def data_retention_remove_all_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["replication"],
                                "policy_to_invoke"    : "irods_policy_data_retention",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                    "plugin_specific_configuration": {
                        "log_errors" : "true",
                        "mode" : "remove_all_replicas"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_retention_trim_single_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["replication"],
                                "policy_to_invoke"    : "irods_policy_data_retention",
                                "configuration" : {
                                    "mode" : "trim_single_replica"
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_retention_with_whitelist_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["replication"],
                                "policy_to_invoke"    : "irods_policy_data_retention",
                                "configuration" : {
                                    "resource_white_list" : ["demoResc", "AnotherResc"]
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                    "plugin_specific_configuration": {
                        "log_errors" : "true",
                        "mode" : "trim_single_replica"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()


    @contextlib.contextmanager
    def data_retention_alternate_attributes_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["replication"],
                                "policy_to_invoke"    : "irods_policy_data_retention",
                                "configuration" : {
                                    "log_errors" : "true",
                                    "attribute"  : "event_handler_attribute",
                                    "mode" : "trim_single_replica"
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                    "plugin_specific_configuration": {
                        "log_errors" : "true",
                        "mode" : "trim_single_replica"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    def test_direct_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput -R rnd ' + filename)
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "rnd"
    },
    "configuration" : {
        "mode" : "trim_single_replica"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_retention_trim_single_direct_invocation_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'from ufs')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    lib.log_command_result('ils -l', out, err, ec)
                    assert(out.find('rnd') == -1)
            finally:
                admin_session.assert_icommand('irm -f ' + filename)

    def test_direct_invocation_with_remove_all(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput -R rnd ' + filename)
            admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

            rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file"
    },
    "configuration" : {
        "mode" : "remove_all_replicas"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

            rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
            with open(rule_file, 'w') as f:
                f.write(rule)

            with self.data_retention_remove_all_direct_invocation_configured():
                admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                admin_session.assert_icommand('ils -l ' + filename, 'STDERR_SINGLELINE', 'does not exist')

    def test_direct_invocation_with_preserve_replicas(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput -R rnd ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::retention::preserve_replicas true')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "AnotherResc"
    },
    "configuration" : {
        "mode" : "trim_single_replica"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_retention_trim_single_direct_invocation_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'rnd')
            finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_retention_trim_single_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -R rnd ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    lib.log_command_result('ils -l', out, err, ec)
                    assert(out.find('rnd') == -1)

                    admin_session.assert_icommand('irepl -R TestResc ' + filename, 'STDOUT')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    lib.log_command_result('ils -l', out, err, ec)
                    assert(out.find('AnotherResc') == -1)
                    
                    admin_session.assert_icommand('irepl -R demoResc ' + filename, 'STDOUT')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    lib.log_command_result('ils -l', out, err, ec)
                    assert(out.find('TestResc') == -1)
                    
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_whitelist(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_retention_with_whitelist_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    lib.log_command_result('ils -l', out, err, ec)
                    assert(out.find('demoResc') == -1)
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_trim_single_preserve_replica(self):
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand('imeta set -R AnotherResc irods::retention::preserve_replicas true')
            with self.data_retention_trim_single_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -R AnotherResc ' + filename)
                    admin_session.assert_icommand('irepl -R demoResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'demoResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_retention",
                      "configuration" : {
                          "mode" : "trim_single_replica"
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_retention_trim_single_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    lib.log_command_result('ils -l', out, err, ec)
                    assert(out.find('demoResc') == -1)
            finally:
                admin_session.assert_icommand('irm -f ' + filename)


    def test_query_invocation_with_remove_all(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
            admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

            rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_query_processor",
    "parameters" : {
          "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
          "query_limit" : 1,
          "query_type" : "general",
          "number_of_threads" : 1,
          "policies_to_invoke" : [
              {
                  "policy_to_invoke" : "irods_policy_data_retention",
                  "configuration" : {
                  }
              }
          ]
     }
}
}
INPUT null
OUTPUT ruleExecOut"""

            rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
            with open(rule_file, 'w') as f:
                f.write(rule)

            with self.data_retention_remove_all_configured():
                admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                admin_session.assert_icommand('ils -l ' + filename, 'STDERR_SINGLELINE', 'does not exist')

    def test_direct_invocation_with_preserve_replicas_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc direct_invocation_attribute true')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "AnotherResc"
    },
    "configuration" : {
         "attribute" : "direct_invocation_attribute"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_retention_alternate_attributes_direct_invocation_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                    admin_session.assert_icommand('irm -f ' + filename)

    def test_event_handler_invocation_with_trim_single_preserve_replica_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand('imeta set -R AnotherResc event_handler_attribute true')
            with self.data_retention_alternate_attributes_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -R AnotherResc ' + filename)
                    admin_session.assert_icommand('irepl -R demoResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)

class TestPolicyEngineDataReplication(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineDataReplication, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineDataReplication, self).tearDown()

    @contextlib.contextmanager
    def data_replication_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_replication_with_event_handler_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read", "write", "rename", "registration"],
                                "policy_to_invoke"    : "irods_policy_data_replication",
                                "configuration" : {
                                    "destination_resource" : "AnotherResc"
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_replication_with_event_handler_metadata_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read", "write", "rename", "registration"],
                                "policy_to_invoke"    : "irods_policy_data_replication",
                                "configuration" : {
                                    "destination_resource" : "AnotherResc"
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_replication_alternate_attributes_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
                    "plugin_specific_configuration": {
                        "log_errors" : "true",
                        "attribute"  : "data_replication_attribute"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def data_replication_alternate_attributes_with_event_handler_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["put", "get", "create", "read", "write", "rename", "registration"],
                                "policy_to_invoke"    : "irods_policy_data_replication",
                                "configuration" : {
                                    "attribute"  : "event_handler_attribute",
                                    "destination_resource" : "AnotherResc"
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
                    "plugin_specific_configuration": {
                        "log_errors" : "true",
                        "attribute"  : "data_replication_attribute"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()


    def test_direct_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_data_replication",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file",
            "source_resource" : "demoResc",
            "destination_resource" : "AnotherResc"
        },
        "configuration" : {
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_replication_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_source_to_destination_map(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_data_replication",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file",
            "source_resource" : "demoResc"
        },
        "configuration" : {
            "source_to_destination_map" : {
                "demoResc" : ["TestResc", "AnotherResc"]
            }
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_replication_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'TestResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_replication_with_event_handler_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename, 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'demoResc'",
              "query_limit" : 10,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_replication",
                      "configuration" : {
                          "destination_resource" : "AnotherResc"
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_replication_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_data_replication",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file",
            "source_resource" : "demoResc",
            "destination_resource" : "AnotherResc"
        },
        "configuration" : {
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_replication_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_replication_alternate_attributes_with_event_handler_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename, 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'demoResc'",
              "query_limit" : 10,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_replication",
                      "configuration" : {
                          "attribute" : "query_processor_attribute",
                          "destination_resource" : "AnotherResc"
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_replication_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)

class TestEventHandlerUserModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerUserModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerUserModified, self).tearDown()

    @contextlib.contextmanager
    def event_handler_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-user_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-user_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "user_name" : "eve"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["create", "modify", "remove"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_configured_fail_conditional(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-user_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-user_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "user_name" : "noteve"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["create", "modify", "remove"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()


    def test_event_handler_user_create(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
                    admin_session.assert_icommand('imeta ls -u ' + user_name, 'STDOUT_SINGLELINE', 'CREATE')
            finally:
                admin_session.assert_icommand('iadmin rmuser ' + user_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_user_create_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            try:
                with self.event_handler_configured_fail_conditional():
                    admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
                    admin_session.assert_icommand('imeta ls -u ' + user_name, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('iadmin rmuser ' + user_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_user_modify(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('iadmin moduser ' + user_name + ' password apass')
                    admin_session.assert_icommand('imeta ls -u ' + user_name, 'STDOUT_SINGLELINE', 'MODIFY')
            finally:
                admin_session.assert_icommand('iadmin rmuser ' + user_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_user_remove(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('iadmin rmuser ' + user_name)
                    admin_session.assert_icommand('imeta ls -u rods', 'STDOUT_SINGLELINE', 'REMOVE')
            finally:
                admin_session.assert_icommand('imeta rm -u rods irods_policy_testing_policy REMOVE')
                admin_session.assert_icommand('iadmin rum')

class TestEventHandlerResourceModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerResourceModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerResourceModified, self).tearDown()

    @contextlib.contextmanager
    def event_handler_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-resource_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-resource_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "source_resource" : "policy_comp_resc"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["create", "modify", "remove"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()

    @contextlib.contextmanager
    def event_handler_configured_fail_conditional(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-resource_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-resource_modified",
                    'plugin_specific_configuration': {
                        "policies_to_invoke" : [
                            {
                                "conditional" : {
                                    "source_resource" : "mumbleresc"
                                },
                                "active_policy_clauses" : ["post"],
                                "events" : ["create", "modify", "remove"],
                                "policy_to_invoke"    : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()


    def test_event_handler_resource_create(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                             (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
                    admin_session.assert_icommand('imeta ls -R ' + resource_name, 'STDOUT_SINGLELINE', 'CREATE')
            finally:
                admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_resource_create_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            try:
                with self.event_handler_configured_fail_conditional():
                    admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                             (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
                    admin_session.assert_icommand('imeta ls -R ' + resource_name, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_resource_modify(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                     (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('iadmin modresc ' + resource_name + ' status delighted')
                    admin_session.assert_icommand('imeta ls -R ' + resource_name, 'STDOUT_SINGLELINE', 'MODIFY')
            finally:
                admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_resource_remove(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                     (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
            try:
                with self.event_handler_configured():
                    admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                    admin_session.assert_icommand('imeta ls -R demoResc', 'STDOUT_SINGLELINE', 'REMOVE')
            finally:
                admin_session.assert_icommand('imeta rm -R demoResc irods_policy_testing_policy REMOVE')
                admin_session.assert_icommand('iadmin rum')

class TestPolicyEngineDataVerification(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineDataVerification, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineDataVerification, self).tearDown()

    @contextlib.contextmanager
    def data_verification_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["replication"],
                                "policy_to_invoke"    : "irods_policy_data_verification",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_verification-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_verification",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()


    @contextlib.contextmanager
    def data_verification_alternate_attributes_configured(self):
        filename = paths.server_config_path()

        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
                {
                    "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                    "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                    "plugin_specific_configuration": {
                        "policies_to_invoke" : [
                            {   "active_policy_clauses" : ["post"],
                                "events" : ["replication"],
                                "policy_to_invoke"    : "irods_policy_data_verification",
                                "configuration" : {
                                    "log_errors" : "true",
                                    "attribute"  : "event_handler_attribute",
                                }
                            }
                        ]
                    }
                }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-data_verification-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-data_verification",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
               {
                    "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                    "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
                    "plugin_specific_configuration": {
                        "log_errors" : "true"
                    }
               }
            )


        try:
            with lib.file_backed_up(filename):
                irods_config.commit(irods_config.server_config, irods_config.server_config_path)
                IrodsController().reload_configuration()
                yield
        finally:
            IrodsController().reload_configuration()


    def test_direct_invocation_verify_catalog(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
    },
    "configuration" : {
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)


# TODO :: add iadmin modrepl for Fail Test
    def test_direct_invocation_verify_catalog_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
    },
    "configuration" : {
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_filesystem(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
    },
    "configuration" : {
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_filesystem_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -L ' + filename, 'STDOUT_SINGLELINE', filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
    },
    "configuration" : {
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
    },
    "configuration" : {
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_checksum_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -L ' + filename, 'STDOUT_SINGLELINE', filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
    },
    "configuration" : {
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_verify_catalog(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


# TODO :: add iadmin modrepl for Fail Test
    def test_event_handler_invocation_verify_catalog_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_verify_filesystem(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



# TODO :: Add MungeFS for Fail Test
    def test_event_handler_invocation_verify_filesystem_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_verify_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



# TODO :: Add MungeFS for Fail Test
    def test_event_handler_invocation_verify_checksum_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with self.data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_catalog(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_catalog_missing_source_resource(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_filesystem(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_filesystem_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_checksum_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_with_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc direct_invocation_attribute filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
    },
    "configuration" : {
         "attribute" : "direct_invocation_attribute"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with self.data_verification_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand('imeta set -R AnotherResc event_handler_attribute filesystem')
            with self.data_verification_alternate_attributes_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)




