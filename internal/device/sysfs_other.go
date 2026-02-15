//go:build !linux

package device

import "fmt"

func resolveFromMajorMinor(majmin string) (devPath, dmName string, warnings []string) {
	_ = majmin
	return "", "", []string{"sysfs resolution is only supported on linux"}
}

func buildStackFromDev(devPath string) []StackNode {
	_ = devPath
	return nil
}

func majorMinorString(devPath string) (string, error) {
	return "", fmt.Errorf("major:minor is only supported on linux")
}
