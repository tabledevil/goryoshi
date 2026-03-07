package tsk

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOpenExtFSDetectsFamily(t *testing.T) {
	for _, fsType := range []string{"ext2", "ext3", "ext4"} {
		t.Run(fsType, func(t *testing.T) {
			image := buildExtImage(t, fsType, 1024, "")
			fs, err := openExtFS(image)
			if err != nil {
				t.Fatalf("openExtFS: %v", err)
			}
			defer fs.close()

			if fs.fsType != fsType {
				t.Fatalf("fsType=%q want %q", fs.fsType, fsType)
			}
		})
	}
}

func TestScanExtractsHiddenExt4Entries(t *testing.T) {
	src := t.TempDir()
	mount := t.TempDir()
	extract := t.TempDir()

	writeFile(t, filepath.Join(src, "visible.txt"), "visible\n")
	writeFile(t, filepath.Join(src, "secret.txt"), "secret\n")
	writeFile(t, filepath.Join(src, "hidden-dir", "nested.txt"), "nested\n")

	writeFile(t, filepath.Join(mount, "visible.txt"), "visible\n")
	if err := os.MkdirAll(filepath.Join(mount, "lost+found"), 0o755); err != nil {
		t.Fatalf("mkdir lost+found: %v", err)
	}

	image := buildExtImage(t, "ext4", 4096, src)

	hidden, err := Scan(image, mount, extract, ScanOptions{
		IgnoreRunDir:  true,
		IgnoreEmpty:   true,
		IgnoreUnalloc: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if hidden != 3 {
		t.Fatalf("hidden=%d want 3", hidden)
	}

	assertFileContent(t, filepath.Join(extract, "secret.txt"), "secret\n")
	assertFileContent(t, filepath.Join(extract, "hidden-dir", "nested.txt"), "nested\n")
	if _, err := os.Stat(filepath.Join(extract, "hidden-dir")); err != nil {
		t.Fatalf("hidden dir not created: %v", err)
	}
}

func TestScanHandlesExt2IndirectBlocks(t *testing.T) {
	src := t.TempDir()
	mount := t.TempDir()
	extract := t.TempDir()

	large := strings.Repeat("abcdef0123456789", 4096)
	writeFile(t, filepath.Join(src, "big.bin"), large)
	if err := os.MkdirAll(filepath.Join(mount, "lost+found"), 0o755); err != nil {
		t.Fatalf("mkdir lost+found: %v", err)
	}

	image := buildExtImage(t, "ext2", 1024, src)

	hidden, err := Scan(image, mount, extract, ScanOptions{
		IgnoreRunDir:  true,
		IgnoreEmpty:   true,
		IgnoreUnalloc: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if hidden != 1 {
		t.Fatalf("hidden=%d want 1", hidden)
	}

	assertFileContent(t, filepath.Join(extract, "big.bin"), large)
}

func TestScanHonorsIgnoreRunDir(t *testing.T) {
	src := t.TempDir()
	mount := t.TempDir()
	extract := t.TempDir()

	writeFile(t, filepath.Join(src, "run", "hidden.txt"), "ephemeral\n")
	if err := os.MkdirAll(filepath.Join(mount, "lost+found"), 0o755); err != nil {
		t.Fatalf("mkdir lost+found: %v", err)
	}

	image := buildExtImage(t, "ext4", 4096, src)

	hidden, err := Scan(image, mount, extract, ScanOptions{
		IgnoreRunDir:  true,
		IgnoreEmpty:   true,
		IgnoreUnalloc: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if hidden != 0 {
		t.Fatalf("hidden=%d want 0", hidden)
	}
}

func TestScanSkipsHiddenSymlinks(t *testing.T) {
	src := t.TempDir()
	mount := t.TempDir()
	extract := t.TempDir()

	writeFile(t, filepath.Join(src, "target.txt"), "target\n")
	if err := os.Symlink("target.txt", filepath.Join(src, "hidden-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(mount, "lost+found"), 0o755); err != nil {
		t.Fatalf("mkdir lost+found: %v", err)
	}
	writeFile(t, filepath.Join(mount, "target.txt"), "target\n")

	image := buildExtImage(t, "ext4", 4096, src)

	hidden, err := Scan(image, mount, extract, ScanOptions{
		IgnoreRunDir:  true,
		IgnoreEmpty:   true,
		IgnoreUnalloc: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if hidden != 0 {
		t.Fatalf("hidden=%d want 0", hidden)
	}
}

func buildExtImage(t *testing.T, fsType string, blockSize int, srcDir string) string {
	t.Helper()

	mke2fsPath, err := exec.LookPath("mke2fs")
	if err != nil {
		t.Skip("mke2fs not available")
	}

	image := filepath.Join(t.TempDir(), fsType+".img")
	args := []string{"-q", "-F", "-t", fsType, "-b", intString(blockSize)}
	if srcDir != "" {
		args = append(args, "-d", srcDir)
	}
	args = append(args, image, "32M")

	cmd := exec.Command(mke2fsPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mke2fs failed: %v\n%s", err, out)
	}
	return image
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("%s content mismatch", path)
	}
}

func intString(v int) string {
	return strconv.Itoa(v)
}
