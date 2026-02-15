//go:build linux

package device

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolveFromMajorMinor(majmin string) (devPath, dmName string, warnings []string) {
	// /sys/dev/block/<maj:min> -> ../../block/dm-0 or ../../block/sda/sda3
	link := filepath.Join("/sys/dev/block", majmin)
	target, err := os.Readlink(link)
	if err != nil {
		return "", "", []string{fmt.Sprintf("sysfs: cannot readlink %s: %v", link, err)}
	}
	abs := filepath.Clean(filepath.Join(filepath.Dir(link), target))
	base := filepath.Base(abs) // dm-0 or sda3

	// Prefer /dev/mapper/<name> for dm-* if present.
	if strings.HasPrefix(base, "dm-") {
		nm := dmNameForDM(base)
		if nm != "" {
			mp := "/dev/mapper/" + nm
			if _, err := os.Stat(mp); err == nil {
				return mp, nm, nil
			}
			dmName = nm
		}
		p := "/dev/" + base
		if _, err := os.Stat(p); err == nil {
			return p, dmName, nil
		}
		return "", dmName, []string{fmt.Sprintf("sysfs: %s maps to %s but no /dev node found", majmin, base)}
	}

	p := "/dev/" + base
	if _, err := os.Stat(p); err == nil {
		return p, "", nil
	}
	return "", "", []string{fmt.Sprintf("sysfs: %s maps to %s but %s does not exist", majmin, base, p)}
}

func dmNameForDM(dmNode string) string {
	b, err := os.ReadFile(filepath.Join("/sys/block", dmNode, "dm", "name"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func dmUUIDForDM(dmNode string) string {
	b, err := os.ReadFile(filepath.Join("/sys/block", dmNode, "dm", "uuid"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func buildStackFromDev(devPath string) []StackNode {
	// For best-effort explanation, resolve to the sysfs block node by major:minor.
	majmin, err := majorMinorString(devPath)
	if err != nil || majmin == "" {
		// If it's a symlinkable /dev/disk/by-* path, eval and retry once.
		if p, err2 := filepath.EvalSymlinks(devPath); err2 == nil && p != devPath {
			majmin, _ = majorMinorString(p)
			devPath = p
		}
	}
	if majmin == "" {
		return nil
	}

	link := filepath.Join("/sys/dev/block", majmin)
	target, err := os.Readlink(link)
	if err != nil {
		return nil
	}
	abs := filepath.Clean(filepath.Join(filepath.Dir(link), target))
	node := filepath.Base(abs) // dm-0, sda3, nvme0n1p2

	seen := map[string]bool{}
	var out []StackNode
	var walk func(name string)
	walk = func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true

		n := StackNode{Name: name}
		if strings.HasPrefix(name, "dm-") {
			n.DMName = dmNameForDM(name)
			n.DMUUID = dmUUIDForDM(name)
			if n.DMName != "" {
				mp := "/dev/mapper/" + n.DMName
				if _, err := os.Stat(mp); err == nil {
					n.Dev = mp
				}
			}
			if n.Dev == "" {
				p := "/dev/" + name
				if _, err := os.Stat(p); err == nil {
					n.Dev = p
				}
			}
		} else {
			p := "/dev/" + name
			if _, err := os.Stat(p); err == nil {
				n.Dev = p
			}
		}

		slavesDir := filepath.Join("/sys/block", name, "slaves")
		ents, err := os.ReadDir(slavesDir)
		if err == nil {
			for _, e := range ents {
				n.Slaves = append(n.Slaves, e.Name())
			}
		}
		out = append(out, n)

		for _, s := range n.Slaves {
			walk(s)
		}
	}

	walk(node)
	return out
}
