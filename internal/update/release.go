package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var RuntimeAssetNames = []string{
	"relayward-agent-launcher",
	"relayward-agent.openrc",
	"relayward-agent.service",
	"uninstall.sh",
}

func RuntimeAssetsSHA256(directory string) (string, error) {
	aggregate := sha256.New()
	for _, name := range RuntimeAssetNames {
		path := filepath.Join(directory, name)
		digest, err := releaseFileSHA256(path)
		if err != nil {
			return "", fmt.Errorf("hash runtime asset %s: %w", name, err)
		}
		if _, err := fmt.Fprintln(aggregate, digest); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(aggregate.Sum(nil)), nil
}

func releaseFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
