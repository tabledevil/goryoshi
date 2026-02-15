//go:build !linux || !cgo

package tsk

import "fmt"

func Scan(volume, mountPoint, extractPath string, opts ScanOptions) (int, error) {
	_ = volume
	_ = mountPoint
	_ = extractPath
	_ = opts
	return 0, fmt.Errorf("scan is only supported on linux with cgo (built with libtsk)")
}
