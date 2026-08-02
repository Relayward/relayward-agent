package buildinfo

import "testing"

func TestCurrent(t *testing.T) {
	info := Current()
	if info.Version == "" || info.Commit == "" || info.Date == "" {
		t.Fatalf("Current() = %+v, want populated fields", info)
	}
}
