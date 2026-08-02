package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/Relayward/relayward-sdk/contract"
)

const (
	ManifestAPIVersion = "relayward.agent-release/v1"
	BinaryAssetName    = "relayward-agent-linux-amd64"
	ManifestAssetName  = "relayward-agent-manifest.json"
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Artifact struct {
	File   string `json:"file"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	APIVersion          string    `json:"api_version"`
	Version             string    `json:"version"`
	PublishedAt         time.Time `json:"published_at"`
	RuntimeAssetsSHA256 string    `json:"runtime_assets_sha256"`
	Artifact            Artifact  `json:"artifact"`
}

func DecodeManifest(reader io.Reader) (Manifest, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var value Manifest
	if err := decoder.Decode(&value); err != nil {
		return Manifest{}, fmt.Errorf("decode Agent release manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("Agent release manifest contains trailing JSON")
	}
	if err := ValidateManifest(value); err != nil {
		return Manifest{}, err
	}
	return value, nil
}

func ValidateManifest(value Manifest) error {
	if value.APIVersion != ManifestAPIVersion {
		return fmt.Errorf("api_version: unsupported value %q", value.APIVersion)
	}
	if err := contract.ValidateSemanticVersion(value.Version); err != nil {
		return fmt.Errorf("version: %w", err)
	}
	if value.PublishedAt.IsZero() {
		return errors.New("published_at: must be set")
	}
	if !sha256Pattern.MatchString(value.RuntimeAssetsSHA256) {
		return errors.New("runtime_assets_sha256: invalid SHA-256 digest")
	}
	if value.Artifact.File != BinaryAssetName || value.Artifact.OS != "linux" || value.Artifact.Arch != "amd64" {
		return errors.New("artifact: must be the Relayward Agent Linux AMD64 binary")
	}
	if value.Artifact.Size <= 0 || value.Artifact.Size > MaximumBinaryBytes {
		return fmt.Errorf("artifact.size: must be between 1 and %d", MaximumBinaryBytes)
	}
	if !sha256Pattern.MatchString(value.Artifact.SHA256) {
		return errors.New("artifact.sha256: invalid SHA-256 digest")
	}
	return nil
}
