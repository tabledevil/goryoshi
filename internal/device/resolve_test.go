package device

import "testing"

func TestParseMountInfoLine(t *testing.T) {
	line := "29 23 8:1 / / rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro"
	mi, ok := parseMountInfoLine(line)
	if !ok {
		t.Fatalf("expected ok")
	}
	if mi.MountPoint != "/" {
		t.Fatalf("mountpoint=%q", mi.MountPoint)
	}
	if mi.FSType != "ext4" {
		t.Fatalf("fstype=%q", mi.FSType)
	}
	if mi.Source != "/dev/sda1" {
		t.Fatalf("source=%q", mi.Source)
	}
	if mi.MajorMinor != "8:1" {
		t.Fatalf("majmin=%q", mi.MajorMinor)
	}
}

func TestUnescapeMountinfo(t *testing.T) {
	got := unescapeMountinfo("/media/My\\040Disk")
	if got != "/media/My Disk" {
		t.Fatalf("got=%q", got)
	}
}
