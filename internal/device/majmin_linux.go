//go:build linux

package device

import (
	"fmt"
	"os"
	"syscall"
)

func majorMinorString(devPath string) (string, error) {
	fi, err := os.Stat(devPath)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("unexpected stat type for %s", devPath)
	}
	// On Linux, Stat_t.Rdev contains the device ID for device special files.
	maj, min := linuxMajorMinor(uint64(st.Rdev))
	return fmt.Sprintf("%d:%d", maj, min), nil
}

// linuxMajorMinor decodes a dev_t using the same scheme as glibc's sysmacros.h.
func linuxMajorMinor(dev uint64) (major uint64, minor uint64) {
	major = (dev & 0x00000000000fff00) >> 8
	major |= (dev & 0xfffff00000000000) >> 32
	minor = (dev & 0x00000000000000ff)
	minor |= (dev & 0x00000ffffff00000) >> 12
	return major, minor
}
