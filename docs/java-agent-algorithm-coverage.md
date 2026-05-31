# Algorithm Coverage

This PoC migrates the JavaScript detector behavior into Java-native detector
methods in `DetectorEngine`. Runtime API hooks call these methods directly where
there is a concrete Java API to instrument. Semantic hook methods exist for
policy families whose original hook point is language- or framework-specific,
so the playground can still verify policy execution and JSONL log collection.

## Accepted Algorithms

`scripts/acceptance.sh` currently requires these algorithms to appear in
`logs/protected/events.jsonl`:

- `request_scanner`
- `request_unusual`
- `xss_userinput`
- `command_reflect`
- `command_userinput`
- `command_common`
- `command_error`
- `command_dnslog`
- `readFile_userinput`
- `readFile_userinput_http`
- `readFile_userinput_unwanted`
- `readFile_unwanted`
- `readFile_outsideWebroot`
- `writeFile_NTFS`
- `writeFile_script`
- `writeFile_reflect`
- `deleteFile_userinput`
- `directory_reflect`
- `directory_userinput`
- `directory_unwanted`
- `ssrf_userinput`
- `ssrf_aws`
- `ssrf_common`
- `ssrf_obfuscate`
- `ssrf_protocol`
- `dns_blacklist`
- `jndi_disable_all`
- `sql_userinput`
- `sql_policy`
- `sql_regex`
- `sql_exception`
- `deserialization_blacklist`
- `xxe_protocol`
- `xxe_file`
- `include_userinput`
- `include_protocol`
- `fileUpload_multipart_script`
- `fileUpload_multipart_html`
- `fileUpload_multipart_exe`
- `fileUpload_webdav`
- `rename_webshell`
- `link_webshell`
- `ognl_blacklist`
- `ognl_length_limit`
- `eval_regex`
- `loadLibrary_unc`
- `response_dataLeak`
- `xss_echo`
- `webshell_eval`
- `webshell_command`
- `webshell_file_put_contents`
- `webshell_callable`
- `webshell_ld_preload`

## Notes

- Commented or disabled-by-default policy toggles from the source JavaScript
  catalog, such as broad "log every command" or "log every native library load",
  are intentionally not enabled in acceptance because they are not abnormal
  behavior signals by themselves.
- Cloud-delivered configuration, dynamic hook delivery, and heartbeat reporting
  remain out of scope for this PoC, matching the current objective.
