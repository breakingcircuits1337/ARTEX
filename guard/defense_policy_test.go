package guard

import (
	"context"
	"strings"
	"testing"
)

func TestDefenseBlocksAllGuardRoles(t *testing.T) {
	t.Setenv("ARTEX_MODE", "defense")
	for name, factory := range map[string]func() *Guard{
		"worker":       New,
		"planner_main": func() *Guard { return NewTargetOnly(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			g := factory()
			for _, tc := range []struct{ name, input string }{
				{"Bash", `{"command":"curl https://example.com"}`},
				{"WebFetch", `{"url":"https://example.com"}`},
				{"shell_send", `{"text":"echo unsafe"}`},
				{"ExecuteExtraTool", `{"tool_name":"mcp__remote__run"}`},
				{"insert_assets", `{"assets":[]}`},
				{"add_task_scope", `{"kind":"cidr","value":"0.0.0.0/0"}`},
			} {
				blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), tc.name, []byte(tc.input))
				if !blocked || !strings.Contains(msg, "defense mode") {
					t.Errorf("%s: blocked=%v message=%q", tc.name, blocked, msg)
				}
			}
			blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "list_assets", []byte(`{"dsl":"port==443"}`))
			if blocked || msg != "" {
				t.Errorf("internal read denied: %v %s", blocked, msg)
			}
			if len(g.Audit()) < 6 {
				t.Fatal("expected denied operations in guard audit")
			}
		})
	}
}

func TestUnknownModeFailsClosed(t *testing.T) {
	t.Setenv("ARTEX_MODE", "typo")
	g := New()
	blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", []byte(`{"command":"whoami"}`))
	if !blocked {
		t.Fatal("invalid mode must not permit tool execution")
	}
}
