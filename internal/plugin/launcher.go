package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	pluginMemoryLimit    = 1 << 30
	pluginOpenFilesLimit = 65536
	pluginProcessLimit   = 256
)

func RunLimitedPlugin(args []string) error {
	if len(args) != 1 || !filepath.IsAbs(args[0]) {
		return errors.New("limited plugin launcher requires one absolute executable path")
	}
	info, err := os.Lstat(args[0])
	if err != nil {
		return fmt.Errorf("inspect limited plugin executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("limited plugin executable must be a regular file")
	}
	for _, limit := range []struct {
		resource int
		value    uint64
		name     string
	}{
		{unix.RLIMIT_DATA, pluginMemoryLimit, "memory"},
		{unix.RLIMIT_NOFILE, pluginOpenFilesLimit, "open files"},
		{unix.RLIMIT_NPROC, pluginProcessLimit, "processes"},
		{unix.RLIMIT_CORE, 0, "core dump"},
	} {
		if err := setHardProcessLimit(limit.resource, limit.value); err != nil {
			return fmt.Errorf("limit plugin %s: %w", limit.name, err)
		}
	}
	return syscall.Exec(args[0], []string{args[0]}, os.Environ())
}

func setHardProcessLimit(resource int, desired uint64) error {
	var inherited unix.Rlimit
	if err := unix.Getrlimit(resource, &inherited); err != nil {
		return err
	}
	if inherited.Max < desired {
		desired = inherited.Max
	}
	return unix.Setrlimit(resource, &unix.Rlimit{Cur: desired, Max: desired})
}
