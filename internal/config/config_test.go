package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	validPin := strings.Repeat("AB:", 31) + "AB"
	tests := []struct {
		name    string
		value   Config
		wantErr bool
	}{
		{name: "HTTPS", value: Config{ServerURL: " https://center.example/ ", StateDirectory: state}},
		{name: "public HTTP", value: Config{ServerURL: "http://center.example:8080", StateDirectory: state, AllowInsecure: true}},
		{name: "certificate pin", value: Config{ServerURL: "https://center.example", StateDirectory: state, ServerCertSHA256: validPin}},
		{name: "HTTP without opt-in", value: Config{ServerURL: "http://center.example", StateDirectory: state}, wantErr: true},
		{name: "HTTP certificate pin", value: Config{ServerURL: "http://center.example", StateDirectory: state, AllowInsecure: true, ServerCertSHA256: strings.Repeat("ab", 32)}, wantErr: true},
		{name: "empty hostname", value: Config{ServerURL: "https://:443", StateDirectory: state}, wantErr: true},
		{name: "credentials", value: Config{ServerURL: "https://user@center.example", StateDirectory: state}, wantErr: true},
		{name: "path", value: Config{ServerURL: "https://center.example/api", StateDirectory: state}, wantErr: true},
		{name: "query", value: Config{ServerURL: "https://center.example?x=1", StateDirectory: state}, wantErr: true},
		{name: "relative state", value: Config{ServerURL: "https://center.example", StateDirectory: "state"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Normalize(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("Normalize() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && test.name == "certificate pin" && got.ServerCertSHA256 != strings.Repeat("ab", 32) {
				t.Fatalf("normalized pin = %q", got.ServerCertSHA256)
			}
		})
	}
}

func TestSaveLoadAndStrictJSON(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config", "config.json")
	want := Config{ServerURL: "https://center.example/", StateDirectory: filepath.Join(directory, "state")}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.ServerURL != "https://center.example" || got.StateDirectory != want.StateDirectory {
		t.Fatalf("Load() = %+v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("config mode = %o", info.Mode().Perm())
	}

	raw := `{"server_url":"https://center.example","state_directory":"` + want.StateDirectory + `","unknown":true}`
	if err := os.WriteFile(path, []byte(raw), 0o640); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Load() unknown field error = %v", err)
	}
}
