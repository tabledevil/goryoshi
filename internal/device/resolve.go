package device

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolvedMount describes how a mountpoint maps to a readable device (or why it doesn't).
type ResolvedMount struct {
	MountPoint string
	FSType     string
	Source     string // mount source from mountinfo or fstab spec
	DevicePath string // resolved /dev/... path that should be read

	// Optional info for explanation/debugging.
	From        string // "mountinfo", "fstab", "cmdline"
	MajorMinor  string // "maj:min" from mountinfo
	DMName      string // dm name if device is dm-crypt/LVM/etc
	DeviceStack []StackNode
	LeafDevices []string // leaf /dev nodes derived from sysfs slaves (useful for acquisition)
	Warnings    []string
}

type StackNode struct {
	Name   string   // e.g. "dm-0", "sda3"
	DMName string   // if present
	DMUUID string   // dm uuid (often indicates CRYPT-LUKS, LVM, etc)
	Dev    string   // best /dev path we know for this node
	Slaves []string // underlying block node names (e.g. "nvme0n1p3")
}

func (r ResolvedMount) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "mountpoint: %s\n", r.MountPoint)
	if r.FSType != "" {
		fmt.Fprintf(&b, "fstype: %s\n", r.FSType)
	}
	if r.From != "" {
		fmt.Fprintf(&b, "resolved-from: %s\n", r.From)
	}
	if r.Source != "" {
		fmt.Fprintf(&b, "mount-source: %s\n", r.Source)
	}
	if r.MajorMinor != "" {
		fmt.Fprintf(&b, "major:minor: %s\n", r.MajorMinor)
	}
	if r.DevicePath != "" {
		fmt.Fprintf(&b, "device: %s\n", r.DevicePath)
	}
	if r.DMName != "" {
		fmt.Fprintf(&b, "dm-name: %s\n", r.DMName)
	}
	if len(r.DeviceStack) > 0 {
		fmt.Fprintf(&b, "device-stack:\n")
		for i, n := range r.DeviceStack {
			fmt.Fprintf(&b, "  %d: %s", i, n.Name)
			if n.DMName != "" {
				fmt.Fprintf(&b, " (dm=%s)", n.DMName)
			}
			if n.DMUUID != "" {
				fmt.Fprintf(&b, " uuid=%s", n.DMUUID)
			}
			if n.Dev != "" {
				fmt.Fprintf(&b, " dev=%s", n.Dev)
			}
			if len(n.Slaves) > 0 {
				fmt.Fprintf(&b, " slaves=%s", strings.Join(n.Slaves, ","))
			}
			fmt.Fprintln(&b)
		}
	}
	if len(r.LeafDevices) > 0 {
		fmt.Fprintf(&b, "underlying-leaves: %s\n", strings.Join(r.LeafDevices, ", "))
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return b.String()
}

func IsExtFamily(fsType string) bool {
	switch fsType {
	case "ext2", "ext3", "ext4":
		return true
	default:
		return false
	}
}

// ResolveForMountpoint determines the best device node to read for a mountpoint.
//
// Preference order:
//  1. /proc/self/mountinfo (authoritative for what's actually mounted)
//  2. /etc/fstab (helps for odd sources like /dev/root or UUID=...)
//  3. /proc/cmdline (root=... fallback for /dev/root)
//
// It also uses sysfs (/sys/dev/block, /sys/block/dm-*/dm/name, /sys/block/*/slaves)
// to map major:minor to /dev/mapper/<name> where possible and to explain dm/LVM/crypt stacks.
func ResolveForMountpoint(mountPoint string) (ResolvedMount, error) {
	if mountPoint == "" || mountPoint[0] != '/' {
		return ResolvedMount{}, fmt.Errorf("mountpoint must be an absolute path: %q", mountPoint)
	}

	mi, err := findMountInfo(mountPoint)
	if err == nil {
		res := ResolvedMount{
			MountPoint: mountPoint,
			FSType:     mi.FSType,
			Source:     mi.Source,
			From:       "mountinfo",
			MajorMinor: mi.MajorMinor,
		}

		dev, dmName, stack, warn := resolveToDevice(mi.Source, mi.MajorMinor, mountPoint)
		res.DevicePath = dev
		res.DMName = dmName
		res.DeviceStack = stack
		res.LeafDevices = leafDevices(stack)
		res.Warnings = append(res.Warnings, warn...)
		return res, nil
	}

	// Fallback: /etc/fstab
	spec, fsType, ok := findFstabSpec(mountPoint)
	if ok {
		res := ResolvedMount{
			MountPoint: mountPoint,
			FSType:     fsType,
			Source:     spec,
			From:       "fstab",
		}
		dev, dmName, stack, warn := resolveToDevice(spec, "", mountPoint)
		res.DevicePath = dev
		res.DMName = dmName
		res.DeviceStack = stack
		res.LeafDevices = leafDevices(stack)
		res.Warnings = append(res.Warnings, warn...)
		return res, nil
	}

	return ResolvedMount{}, fmt.Errorf("mountpoint %q not found in /proc/self/mountinfo and no matching /etc/fstab entry", mountPoint)
}

type mountInfo struct {
	MountPoint string
	FSType     string
	Source     string
	MajorMinor string
}

func findMountInfo(mountPoint string) (mountInfo, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return mountInfo{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		mi, ok := parseMountInfoLine(line)
		if !ok {
			continue
		}
		if mi.MountPoint == mountPoint {
			return mi, nil
		}
	}
	if err := sc.Err(); err != nil {
		return mountInfo{}, err
	}
	return mountInfo{}, errors.New("not found")
}

func parseMountInfoLine(line string) (mountInfo, bool) {
	parts := strings.SplitN(line, " - ", 2)
	if len(parts) != 2 {
		return mountInfo{}, false
	}
	pre := strings.Fields(parts[0])
	post := strings.Fields(parts[1])
	if len(pre) < 5 || len(post) < 2 {
		return mountInfo{}, false
	}
	majmin := pre[2]
	mp := unescapeMountinfo(pre[4])
	fsType := post[0]
	source := unescapeMountinfo(post[1])
	return mountInfo{
		MountPoint: mp,
		FSType:     fsType,
		Source:     source,
		MajorMinor: majmin,
	}, true
}

func unescapeMountinfo(s string) string {
	// mountinfo uses octal escapes like \040 for space.
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		o1, o2, o3 := s[i+1], s[i+2], s[i+3]
		if o1 < '0' || o1 > '7' || o2 < '0' || o2 > '7' || o3 < '0' || o3 > '7' {
			b.WriteByte(s[i])
			continue
		}
		val := (o1-'0')*64 + (o2-'0')*8 + (o3 - '0')
		b.WriteByte(byte(val))
		i += 3
	}
	return b.String()
}

func findFstabSpec(mountPoint string) (spec string, fsType string, ok bool) {
	f, err := os.Open("/etc/fstab")
	if err != nil {
		return "", "", false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mp := unescapeFstab(fields[1])
		if mp != mountPoint {
			continue
		}
		return fields[0], fields[2], true
	}
	return "", "", false
}

func unescapeFstab(s string) string {
	// fstab also uses octal escapes (\040).
	return unescapeMountinfo(s)
}

func resolveToDevice(source, majmin, mountPoint string) (devPath, dmName string, stack []StackNode, warnings []string) {
	// Best-effort: if we have major:minor, prefer resolving via sysfs because it represents what is actually mounted
	// (including dm-crypt and LVM stacks) even when the mount source is something generic like /dev/root.
	if majmin != "" {
		p2, dm2, warn := resolveFromMajorMinor(majmin)
		if p2 != "" {
			devPath = p2
			dmName = dm2
		}
		warnings = append(warnings, warn...)
	}

	// If mountinfo source is already a /dev path and exists, that's usually the best (mapper/LV/decrypted device).
	if devPath == "" && strings.HasPrefix(source, "/dev/") {
		if source == "/dev/root" || source == "/dev/rootfs" {
			root := rootFromCmdline()
			if root != "" {
				source = root
				warnings = append(warnings, "mount source is /dev/root; resolved using /proc/cmdline root=")
			}
		}
		if p, err := resolveFSSpecToDev(source); err == nil && p != "" {
			devPath = p
		} else {
			// Accept it even if it doesn't exist (containers, initramfs), but scanning will fail later.
			devPath = source
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("could not verify device exists: %v", err))
			}
		}
	} else if devPath == "" {
		// UUID=/LABEL=/crypttab name/dm-* fallback.
		if p, err := resolveFSSpecToDev(source); err == nil && p != "" {
			devPath = p
		}
	}

	// If we resolved to a /dev/mapper/*, map it to dm name and build an explanation stack.
	if devPath != "" {
		stack = buildStackFromDev(devPath)
		if dmName == "" {
			for _, n := range stack {
				if n.DMName != "" {
					dmName = n.DMName
					break
				}
			}
		}
	}

	// crypttab hint: if fstab references UUID=... and that UUID is a crypt source, the mounted device will
	// still be /dev/mapper/<name>. We don't override devPath automatically, but we surface the mapping.
	if strings.HasPrefix(source, "UUID=") || strings.HasPrefix(source, "LABEL=") {
		if name, src := crypttabMatch(source); name != "" {
			warnings = append(warnings, fmt.Sprintf("crypttab: %s maps to %s (device to scan is typically /dev/mapper/%s if mounted)", source, src, name))
		}
	}

	if devPath == "" && majmin == "" {
		warnings = append(warnings, "no major:minor available; cannot resolve dm stack via sysfs")
	}
	_ = mountPoint
	return devPath, dmName, stack, warnings
}

func leafDevices(stack []StackNode) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range stack {
		if len(n.Slaves) != 0 {
			continue
		}
		dev := n.Dev
		if dev == "" && n.Name != "" {
			dev = "/dev/" + n.Name
		}
		if dev == "" || seen[dev] {
			continue
		}
		seen[dev] = true
		out = append(out, dev)
	}
	return out
}

func resolveFSSpecToDev(spec string) (string, error) {
	switch {
	case strings.HasPrefix(spec, "/dev/"):
		// If it exists, normalize symlinks.
		if _, err := os.Stat(spec); err != nil {
			return spec, err
		}
		p, err := filepath.EvalSymlinks(spec)
		if err == nil {
			return p, nil
		}
		return spec, nil
	case strings.HasPrefix(spec, "UUID="):
		u := strings.TrimPrefix(spec, "UUID=")
		return resolveByUUID(u)
	case strings.HasPrefix(spec, "LABEL="):
		l := strings.TrimPrefix(spec, "LABEL=")
		return resolveByLabel(l)
	default:
		// Some fstab entries use a bare mapper name; try crypttab then /dev/mapper/<name>.
		if name, _ := crypttabForName(spec); name != "" {
			mp := "/dev/mapper/" + name
			if _, err := os.Stat(mp); err == nil {
				return mp, nil
			}
		}
		mp := "/dev/mapper/" + spec
		if _, err := os.Stat(mp); err == nil {
			return mp, nil
		}
		return "", fmt.Errorf("unsupported/unknown fs spec: %q", spec)
	}
}

func resolveByUUID(uuid string) (string, error) {
	p := filepath.Join("/dev/disk/by-uuid", uuid)
	if _, err := os.Lstat(p); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func resolveByLabel(label string) (string, error) {
	p := filepath.Join("/dev/disk/by-label", label)
	if _, err := os.Lstat(p); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func rootFromCmdline() string {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, tok := range strings.Fields(string(b)) {
		if strings.HasPrefix(tok, "root=") {
			return strings.TrimPrefix(tok, "root=")
		}
	}
	return ""
}

func crypttabMatch(spec string) (name, source string) {
	// If spec is UUID=... or LABEL=..., scan crypttab sources to see if it matches.
	f, err := os.Open("/etc/crypttab")
	if err != nil {
		return "", ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n := fields[0]
		src := fields[1]
		if src == spec {
			return n, src
		}
	}
	return "", ""
}

func crypttabForName(name string) (string, string) {
	// Return (name, source) if crypttab defines it.
	f, err := os.Open("/etc/crypttab")
	if err != nil {
		return "", ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == name {
			return fields[0], fields[1]
		}
	}
	return "", ""
}
