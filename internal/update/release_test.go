package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeAssetsSHA256IsStableAndComplete(t *testing.T) {
	directory := t.TempDir()
	for _, name := range RuntimeAssetNames {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	first, err := RuntimeAssetsSHA256(directory)
	if err != nil || len(first) != 64 {
		t.Fatalf("RuntimeAssetsSHA256() = %q, %v", first, err)
	}
	if err := os.WriteFile(filepath.Join(directory, RuntimeAssetNames[1]), []byte("changed\n"), 0o600); err != nil {
		t.Fatalf("change runtime asset: %v", err)
	}
	second, err := RuntimeAssetsSHA256(directory)
	if err != nil || first == second {
		t.Fatalf("changed RuntimeAssetsSHA256() = %q, %v", second, err)
	}
}
