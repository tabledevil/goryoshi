package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tabledevil/goryoshi/internal/device"
	"github.com/tabledevil/goryoshi/internal/tsk"
)

func main() {
	var (
		volume        string
		mountPoint    string
		extractPath   string
		explainDev    bool
		force         bool
		ignoreRun     bool
		ignoreEmpty   bool
		ignoreUnalloc bool
	)

	flag.StringVar(&volume, "volume", "", "Block device, mapper device, or disk image to scan. If empty, auto-resolve from --mount.")
	flag.StringVar(&mountPoint, "mount", "", "Mountpoint corresponding to the filesystem to compare against userspace view (required).")
	flag.StringVar(&extractPath, "extract", "", "Directory to write extracted hidden files/dirs to (required unless --explain-device).")
	flag.BoolVar(&explainDev, "explain-device", false, "Resolve and print the best device to read for --mount, including dm/LVM/crypt stack, then exit.")
	flag.BoolVar(&force, "force", false, "Proceed even if mount filesystem type is not ext2/3/4.")
	flag.BoolVar(&ignoreRun, "ignore-run", true, "Ignore /run (reduces false positives).")
	flag.BoolVar(&ignoreEmpty, "ignore-empty", true, "Ignore empty files (reduces false positives).")
	flag.BoolVar(&ignoreUnalloc, "ignore-unalloc", true, "Ignore entries with unallocated names (reduces false positives).")
	flag.Parse()

	if mountPoint == "" {
		fmt.Fprintln(os.Stderr, "error: --mount is required")
		os.Exit(2)
	}

	mp, err := filepath.EvalSymlinks(mountPoint)
	if err != nil {
		// Not fatal; mountpoint can be a non-symlink path.
		mp = mountPoint
	}
	mp = filepath.Clean(mp)

	res, err := device.ResolveForMountpoint(mp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error resolving device:", err)
		os.Exit(2)
	}

	if explainDev {
		fmt.Print(res.Explain())
		return
	}

	if volume == "" {
		if res.DevicePath == "" {
			fmt.Fprintln(os.Stderr, "error: could not resolve a readable device path; re-run with --explain-device")
			os.Exit(2)
		}
		volume = res.DevicePath
	}

	if extractPath == "" {
		fmt.Fprintln(os.Stderr, "error: --extract is required")
		os.Exit(2)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: root privileges required to read raw block devices")
		os.Exit(2)
	}

	if !force && !device.IsExtFamily(res.FSType) {
		fmt.Fprintf(os.Stderr, "error: mountpoint %q filesystem type %q is not ext2/3/4 (use --force to override)\n", mp, res.FSType)
		os.Exit(2)
	}

	hidden, err := tsk.Scan(volume, mp, extractPath, tsk.ScanOptions{
		IgnoreRunDir:  ignoreRun,
		IgnoreEmpty:   ignoreEmpty,
		IgnoreUnalloc: ignoreUnalloc,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}
	os.Exit(hidden)
}
