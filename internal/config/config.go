package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const maxConfigBytes = 1 << 20

type Config struct {
	ServerURL        string `json:"server_url"`
	StateDirectory   string `json:"state_directory"`
	AllowInsecure    bool   `json:"allow_insecure"`
	ServerCertSHA256 string `json:"server_cert_sha256,omitempty"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("config must be a regular file")
	}
	if info.Size() > maxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxConfigBytes+1))
	decoder.DisallowUnknownFields()
	var value Config
	if err := decoder.Decode(&value); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("config contains trailing JSON")
	}
	return Normalize(value)
}

func Save(path string, value Config) error {
	normalized, err := Normalize(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	raw, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	raw = append(raw, '\n')
	temporary, err := os.CreateTemp(directory, ".relayward-agent-config-*")
	if err != nil {
		return fmt.Errorf("create config temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return fmt.Errorf("protect config temporary file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return syncDirectory(directory)
}

func Normalize(value Config) (Config, error) {
	value.ServerURL = strings.TrimSpace(value.ServerURL)
	parsed, err := url.Parse(value.ServerURL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return Config{}, errors.New("server_url must be an absolute center URL without credentials, path, query, or fragment")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !value.AllowInsecure {
			return Config{}, errors.New("plain HTTP server_url requires allow_insecure")
		}
	default:
		return Config{}, errors.New("server_url must use HTTP or HTTPS")
	}
	parsed.Path = ""
	value.ServerURL = strings.TrimSuffix(parsed.String(), "/")
	if !filepath.IsAbs(value.StateDirectory) || filepath.Clean(value.StateDirectory) != value.StateDirectory {
		return Config{}, errors.New("state_directory must be an absolute clean path")
	}
	value.ServerCertSHA256 = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value.ServerCertSHA256), ":", ""))
	if value.ServerCertSHA256 != "" {
		if parsed.Scheme != "https" {
			return Config{}, errors.New("server_cert_sha256 requires an HTTPS server_url")
		}
		digest, err := hex.DecodeString(value.ServerCertSHA256)
		if err != nil || len(digest) != sha256.Size {
			return Config{}, errors.New("server_cert_sha256 must be a SHA-256 hexadecimal digest")
		}
	}
	return value, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
