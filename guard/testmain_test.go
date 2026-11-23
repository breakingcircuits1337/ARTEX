package guard

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestMain(m *testing.M) {
	// Guard fixtures exercise pentest/intercept behavior. Explicit test-only
	// opt-in preserves those expectations without relaxing the application's
	// defense-by-default policy.
	if os.Getenv("ARTEX_MODE") == "" {
		os.Setenv("ARTEX_MODE", "pentest")
	}
	// Own database per package (#80), as in db, agent, server, evidence and intercept.
	db.SuffixTestDatabase("guard")
	os.Exit(m.Run())
}
