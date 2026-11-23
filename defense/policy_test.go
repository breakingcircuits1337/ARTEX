package defense

import "testing"

func TestModeValidation(t *testing.T) {
 for _, tc := range []struct { value, mode string; restricted, invalid bool }{
  {"", "pentest", false, false},
  {"pentest", "pentest", false, false},
  {"DEFENSE", "defense", true, false},
  {" typo ", "typo", true, true},
 } {
  t.Setenv("ARTEX_MODE", tc.value)
  if got := Mode(); got != tc.mode { t.Errorf("%q: mode=%q", tc.value, got) }
  if Restricted() != tc.restricted { t.Errorf("%q: restricted mismatch", tc.value) }
  if (Validate() != nil) != tc.invalid { t.Errorf("%q: validation mismatch", tc.value) }
 }
}

func TestPolicyDenyByDefault(t *testing.T) {
 for _, name := range []string{"Bash", "shell_open", "shell_send", "WebFetch",
 "web_search", "Skill", "ExecuteExtraTool", "Write", "Edit", "MultiEdit",
 "insert_assets", "add_task_scope", "list_task_credentials", "traffic_replay",
 "mcp__remote__run", "custom_scan", ""} {
  if ToolAllowed(name) { t.Errorf("unsafe tool %q allowed", name) }
 }
 for _, name := range []string{"Read", "Grep", "list_assets", "assess_exposure", "record_fact", "graph_overview"} {
  if !ToolAllowed(name) { t.Errorf("reviewed tool %q denied", name) }
 }
}
