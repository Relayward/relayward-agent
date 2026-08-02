package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	updatepkg "github.com/Relayward/relayward-agent/internal/update"
)

func TestCreateManifest(t *testing.T) {
	directory := t.TempDir()
	binary := []byte("test Agent binary")
	if err := os.WriteFile(filepath.Join(directory, updatepkg.BinaryAssetName), binary, 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	for _, name := range updatepkg.RuntimeAssetNames {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := createManifest(directory, "0.1.0", "2026-08-02T10:00:00Z"); err != nil {
		t.Fatalf("createManifest() error = %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, updatepkg.ManifestAssetName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest updatepkg.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if err := updatepkg.ValidateManifest(manifest); err != nil {
		t.Fatalf("ValidateManifest() error = %v", err)
	}
	if manifest.Version != "0.1.0" || manifest.Artifact.Size != int64(len(binary)) {
		t.Fatalf("manifest = %+v", manifest)
	}
}
