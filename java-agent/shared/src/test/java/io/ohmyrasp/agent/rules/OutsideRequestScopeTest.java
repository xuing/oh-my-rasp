package io.ohmyrasp.agent.rules;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The block-scope classes both engines decide with (docs/detection.md, "Outside an HTTP request", has the table):
 * which findings block outside a request whatever {@code outside_request} says, which log whatever it says, and which
 * follow it.
 */
final class OutsideRequestScopeTest {
  @Test
  void anExploitShapedArgumentIsIntrinsicOnBothEngines() {
    String[][] intrinsic = {
      {"base64_avx512_tail_underflow", null},
      {"jndi_disable_all", "url_scheme_selection"},
      {"jndi_remote_lookup", null},
      {"jndi_jaas_config", null},
      {"jaas_jndi_remote_provider", null},
      {"deserialization_gadget", null},
      {"deserialization_gadget_class", "resolved_class"},
      {"deserialization_protocol_class", "non_throwable_constructor"},
      {"deserialization_hessian_type", null},
      {"deserialization_fastjson_resource_url", null},
      {"deserialization_xmlrpc_serialized", null},
      {"command_spring_remote_init", "remote_bean_init_dispatch"},
      {"command_execution_exploit_primitive", "remote_bean_init_dispatch"},
      {"command_common", null},
      {"command_execution_exploit_primitive", "command_arguments"},
      {"command_execution_exploit_primitive", "object_deserialization"},
      {"command_execution_exploit_primitive", "xml_deserialization"},
      {"command_config_injection", "configuration_launcher"},
      {"command_execution_shell_meta", "configuration_launcher"},
      {"request_jwt_verification_failure", "rejected_token_dispatch"},
      // The CXF XOP attachment that opened a host file: ssrf_protocol on the primary, a file read on the backports.
      {"ssrf_protocol", "attachment_file_open"},
      {"file_sensitive_read", "attachment_file_open"},
    };
    for (String[] row : intrinsic) {
      assertEquals(OutsideRequest.INTRINSIC, OutsideRequest.scope(row[0], row[1]), row[0] + "/" + row[1]);
    }
  }

  @Test
  void anOperationOnlyFindingIsOperationOnBothEngines() {
    String[][] operation = {
      {"ssrf_aws", null},
      {"ssrf_cloud_metadata", null},
      {"ssrf_protocol", null},
      {"ssrf_obfuscate", null},
      {"ssrf_userinput", "destination_only"},
      {"xxe_protocol", "parser_url_open"},
      {"xxe_external_entity_protocol", null},
      {"classloader_remote", "url_class_definition"},
      {"classloader_remote_codebase", null},
      {"spring_remote_config", null},
      {"script_runtime", "expression_evaluation"},
      {"spel_runtime", "expression_evaluation"},
      {"command_execution_exploit_primitive", "expression_evaluation"},
      {"command_execution_exploit_primitive", "database_stack"},
      {"command_execution_shell_meta", "scheduled_script"},
    };
    for (String[] row : operation) {
      assertEquals(OutsideRequest.OPERATION, OutsideRequest.scope(row[0], row[1]), row[0] + "/" + row[1]);
    }
  }

  @Test
  void everythingElseFollowsTheSetting() {
    String[][] context = {
      {"readFile_unwanted", null},
      {"file_sensitive_read", null},
      {"writeFile_script", null},
      {"file_script_write", null},
      {"java_compile_runtime", null},
      {"java_compile_runtime_execution", null},
      {"jdbc_mysql_deserialization", null},
      {"xml_decoder_runtime", null},
      {"ssrf_common", null},
      {"command_dnslog", null},
      {"command_config_listener", null},
      {"command_execution_exploit_primitive", "configured_listener"},
      {"archive_traversal", null},
      // Expression text with a runtime primitive (CodeExecutionDetector), not an evaluator frame alone.
      {"spel_runtime", null},
      {null, null},
    };
    for (String[] row : context) {
      assertEquals(OutsideRequest.CONTEXT, OutsideRequest.scope(row[0], row[1]), row[0] + "/" + row[1]);
    }
  }

  @Test
  void requestEvidenceAlwaysPermitsAndOutsideTheClassDecides() {
    for (int scope : new int[] {OutsideRequest.CONTEXT, OutsideRequest.INTRINSIC, OutsideRequest.OPERATION}) {
      assertTrue(OutsideRequest.mayBlock(scope, true, false), "inside a request, scope " + scope);
      assertTrue(OutsideRequest.mayBlock(scope, true, true), "inside a request, scope " + scope);
    }
    assertTrue(OutsideRequest.mayBlock(OutsideRequest.INTRINSIC, false, false), "intrinsic with log");
    assertFalse(OutsideRequest.mayBlock(OutsideRequest.OPERATION, false, true), "operation with block");
    assertTrue(OutsideRequest.mayBlock(OutsideRequest.CONTEXT, false, true));
    assertFalse(OutsideRequest.mayBlock(OutsideRequest.CONTEXT, false, false));
  }

  @Test
  void theFamilyIsTheRuleWithoutTheLinePrefix() {
    assertEquals("jndi_remote_lookup", OutsideRequest.family("java8_jndi_remote_lookup"));
    assertEquals("file_sensitive_read", OutsideRequest.family("java11_file_sensitive_read"));
    assertEquals("ssrf_cloud_metadata", OutsideRequest.family("java17_ssrf_cloud_metadata"));
    assertEquals("javascript_runtime", OutsideRequest.family("javascript_runtime"));
    assertEquals("java_compile_runtime", OutsideRequest.family("java_compile_runtime"));
    assertEquals("jndi_disable_all", OutsideRequest.family("jndi_disable_all"));
    assertEquals(null, OutsideRequest.family(null));
  }
}
