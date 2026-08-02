package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Relayward/relayward-sdk/contract"

	updatepkg "github.com/Relayward/relayward-agent/internal/update"
)

func main() {
	dist := flag.String("dist", "dist", "release asset directory")
	version := flag.String("version", "", "semantic release version without a leading v")
	publishedAt := flag.String("published-at", "", "RFC3339 release timestamp")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "relayward-agent-release: unexpected positional arguments")
		os.Exit(2)
	}
	if err := createManifest(*dist, *version, *publishedAt); err != nil {
		fmt.Fprintln(os.Stderr, "relayward-agent-release:", err)
		os.Exit(1)
	}
}

func createManifest(dist, version, publishedAt string) error {
	if err := contract.ValidateSemanticVersion(version); err != nil {
		return fmt.Errorf("version: %w", err)
	}
	published, err := time.Parse(time.RFC3339, publishedAt)
	if err != nil {
		return errors.New("published-at must be RFC3339")
	}
	binaryPath := filepath.Join(dist, updatepkg.BinaryAssetName)
	info, err := os.Lstat(binaryPath)
	if err != nil {
		return fmt.Errorf("inspect release binary: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > updatepkg.MaximumBinaryBytes {
		return errors.New("release binary is not a valid regular file")
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read release binary: %w", err)
	}
	digest := sha256.Sum256(binary)
	runtimeDigest, err := updatepkg.RuntimeAssetsSHA256(dist)
	if err != nil {
		return err
	}
	manifest := updatepkg.Manifest{
		APIVersion: updatepkg.ManifestAPIVersion,
		Version:    version, PublishedAt: published.UTC(), RuntimeAssetsSHA256: runtimeDigest,
		Artifact: updatepkg.Artifact{
			File: updatepkg.BinaryAssetName, OS: "linux", Arch: "amd64",
			Size: info.Size(), SHA256: hex.EncodeToString(digest[:]),
		},
	}
	if err := updatepkg.ValidateManifest(manifest); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(filepath.Join(dist, updatepkg.ManifestAssetName), raw, 0o644)
}
