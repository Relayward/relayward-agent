package plugin

import (
	"os"
	"testing"

	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"github.com/Relayward/relayward-sdk/pluginfixture"
)

func TestMain(m *testing.M) {
	if os.Getenv(nodepluginv1.EnvironmentSocketPath) != "" {
		os.Exit(pluginfixture.Run("1.2.3"))
	}
	os.Exit(m.Run())
}
