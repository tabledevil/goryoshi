package tsk

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	extMagic             = 0xEF53
	extRootInode         = 2
	extFeatureCompatJrnl = 0x0004
	extFeatureIncompatEx = 0x0040
	extFeatureIncompat64 = 0x0080
	extInodeFlagExtents  = 0x00080000

	extExtentMagic = 0xF30A

	extModeTypeMask = 0xF000
	extModeReg      = 0x8000
	extModeDir      = 0x4000
	extModeLnk      = 0xA000
)

type extFS struct {
	f              *os.File
	sizeBytes      int64
	blockSize      uint64
	firstDataBlock uint32
	blocksPerGroup uint32
	inodesPerGroup uint32
	inodesCount    uint64
	blocksCount    uint64
	inodeSize      uint16
	descSize       uint16
	featureCompat  uint32
	featureIncomp  uint32
	groups         []extGroupDesc
	fsType         string
}

type extGroupDesc struct {
	inodeTable uint64
}

type extInode struct {
	number uint32
	mode   uint16
	flags  uint32
	size   uint64
	iBlock [60]byte
}

type extDirEntry struct {
	inode uint32
	name  string
}

type blockRun struct {
	logical     uint64
	physical    uint64
	count       uint64
	initialized bool
}

type visibilityCache struct {
	dirs map[string]map[string]struct{}
}

type scanner struct {
	fs         *extFS
	mountPoint string
	extractDir string
	opts       ScanOptions
	visible    visibilityCache
	seenDirs   map[uint32]bool
	hidden     int
}

func Scan(volume, mountPoint, extractPath string, opts ScanOptions) (int, error) {
	fs, err := openExtFS(volume)
	if err != nil {
		return 0, err
	}
	defer fs.close()

	fmt.Printf("%s (%dMB) -> %s (%d inodes)\n",
		volume,
		fs.sizeBytes/1_000_000,
		fs.fsType,
		fs.inodesCount,
	)

	s := scanner{
		fs:         fs,
		mountPoint: filepath.Clean(mountPoint),
		extractDir: filepath.Clean(extractPath),
		opts:       opts,
		visible:    visibilityCache{dirs: make(map[string]map[string]struct{})},
		seenDirs:   make(map[uint32]bool),
	}

	if err := s.walkDir(extRootInode, ""); err != nil {
		return s.hidden, err
	}

	if s.hidden > 0 {
		fmt.Printf("%d hidden file(s) found\nExtracted to: %s\n", s.hidden, s.extractDir)
	} else {
		fmt.Println("No hidden files found")
	}
	return s.hidden, nil
}

func openExtFS(path string) (*extFS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	sb := make([]byte, 1024)
	if _, err := f.ReadAt(sb, 1024); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s is not a valid volume or disk image", path)
	}

	if le16(sb, 0x38) != extMagic {
		f.Close()
		return nil, fmt.Errorf("%s does not contain a supported filesystem", path)
	}

	blockSize := uint64(1024) << le32(sb, 0x18)
	inodeSize := le16(sb, 0x58)
	if inodeSize == 0 {
		inodeSize = 128
	}

	featureCompat := le32(sb, 0x5C)
	featureIncomp := le32(sb, 0x60)
	descSize := le16(sb, 0xFE)
	if descSize < 32 {
		descSize = 32
	}

	blocksCount := uint64(le32(sb, 0x04))
	if featureIncomp&extFeatureIncompat64 != 0 {
		blocksCount |= uint64(le32(sb, 0x150)) << 32
	}

	inodesCount := uint64(le32(sb, 0x00))
	inodesPerGroup := le32(sb, 0x28)
	blocksPerGroup := le32(sb, 0x20)
	firstDataBlock := le32(sb, 0x14)
	if inodesPerGroup == 0 || blocksPerGroup == 0 {
		f.Close()
		return nil, fmt.Errorf("%s does not contain a supported filesystem", path)
	}

	groupCount := divCeil64(inodesCount, uint64(inodesPerGroup))
	gdtOffset := int64(blockSize)
	if blockSize == 1024 {
		gdtOffset = 2048
	}

	descBuf := make([]byte, int(groupCount)*int(descSize))
	if _, err := f.ReadAt(descBuf, gdtOffset); err != nil {
		f.Close()
		return nil, fmt.Errorf("read group descriptors: %w", err)
	}

	groups := make([]extGroupDesc, 0, groupCount)
	for i := uint64(0); i < groupCount; i++ {
		off := int(i) * int(descSize)
		entry := descBuf[off : off+int(descSize)]
		table := uint64(le32(entry, 0x08))
		if descSize >= 64 {
			table |= uint64(le32(entry, 0x28)) << 32
		}
		groups = append(groups, extGroupDesc{inodeTable: table})
	}

	return &extFS{
		f:              f,
		sizeBytes:      st.Size(),
		blockSize:      blockSize,
		firstDataBlock: firstDataBlock,
		blocksPerGroup: blocksPerGroup,
		inodesPerGroup: inodesPerGroup,
		inodesCount:    inodesCount,
		blocksCount:    blocksCount,
		inodeSize:      inodeSize,
		descSize:       descSize,
		featureCompat:  featureCompat,
		featureIncomp:  featureIncomp,
		groups:         groups,
		fsType:         detectExtType(featureCompat, featureIncomp),
	}, nil
}

func detectExtType(featureCompat, featureIncomp uint32) string {
	if featureIncomp&extFeatureIncompat64 != 0 || featureIncomp&extFeatureIncompatEx != 0 {
		return "ext4"
	}
	if featureCompat&extFeatureCompatJrnl != 0 {
		return "ext3"
	}
	return "ext2"
}

func (fs *extFS) close() {
	if fs != nil && fs.f != nil {
		_ = fs.f.Close()
	}
}

func (s *scanner) walkDir(inodeNum uint32, relPath string) error {
	if s.seenDirs[inodeNum] {
		return nil
	}
	s.seenDirs[inodeNum] = true

	inode, err := s.fs.readInode(inodeNum)
	if err != nil {
		return err
	}
	entries, err := s.fs.readDirEntries(inode)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.name == "." || entry.name == ".." {
			continue
		}

		child, err := s.fs.readInode(entry.inode)
		if err != nil {
			fmt.Printf("Failed to read inode %d\n", entry.inode)
			continue
		}
		if child.isSymlink() {
			continue
		}

		childRel := entry.name
		if relPath != "" {
			childRel = relPath + "/" + entry.name
		}
		if s.opts.IgnoreRunDir && isRunPath(childRel) {
			continue
		}
		if s.opts.IgnoreEmpty && child.isRegular() && child.size == 0 {
			continue
		}

		parentPath := s.mountPoint
		if relPath != "" {
			parentPath = filepath.Join(parentPath, relPath)
		}
		visible, err := s.visible.contains(parentPath, entry.name)
		if err != nil {
			fmt.Printf("Failed to open directory: %s (%v)\n", parentPath, err)
			continue
		}
		if !visible {
			fullPath := filepath.Join(s.mountPoint, childRel)
			fmt.Printf("Hidden: %s (%d)\n", fullPath, entry.inode)
			s.hidden++

			switch {
			case child.isDir():
				outDir := filepath.Join(s.extractDir, childRel)
				if err := os.MkdirAll(outDir, 0o700); err != nil {
					fmt.Printf("Failed to create: %s\n", outDir)
				} else {
					fmt.Printf("Created: %s\n", outDir)
				}
			case child.isRegular():
				s.extractRegular(child, childRel)
			}
		}

		if child.isDir() {
			if err := s.walkDir(entry.inode, childRel); err != nil {
				return err
			}
		}
	}

	return nil
}

func (fs *scanner) extractRegular(inode extInode, relPath string) {
	outPath := filepath.Join(fs.extractDir, relPath)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		fmt.Printf("Failed to create: %s\n", outPath)
		return
	}

	out, err := os.Create(outPath)
	if err != nil {
		fmt.Printf("Failed to create: %s\n", outPath)
		return
	}
	defer out.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	writer := io.MultiWriter(out, md5h, sha1h)

	written, err := fs.fs.copyFileData(inode, writer)
	if err != nil {
		fmt.Printf("Failed to extract: %s\n", outPath)
		return
	}
	if written != inode.size {
		fmt.Printf("Warning: extracted size mismatch for %s (wrote=%d expected=%d)\n",
			outPath, written, inode.size)
	}

	fmt.Printf("Extracted: %s | MD5=%s SHA1=%s\n",
		outPath,
		hashString(md5h),
		hashString(sha1h),
	)
}

func (c *visibilityCache) contains(dirPath, name string) (bool, error) {
	if entries, ok := c.dirs[dirPath]; ok {
		_, found := entries[name]
		return found, nil
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
			c.dirs[dirPath] = nil
			return false, nil
		}
		return false, err
	}

	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = struct{}{}
	}
	c.dirs[dirPath] = names
	_, found := names[name]
	return found, nil
}

func (fs *extFS) readInode(inodeNum uint32) (extInode, error) {
	if inodeNum == 0 || uint64(inodeNum) > fs.inodesCount {
		return extInode{}, fmt.Errorf("inode %d out of range", inodeNum)
	}

	group := (inodeNum - 1) / fs.inodesPerGroup
	index := (inodeNum - 1) % fs.inodesPerGroup
	if int(group) >= len(fs.groups) {
		return extInode{}, fmt.Errorf("inode group %d out of range", group)
	}

	tableBlock := fs.groups[group].inodeTable
	offset := int64(tableBlock)*int64(fs.blockSize) + int64(index)*int64(fs.inodeSize)
	buf := make([]byte, int(fs.inodeSize))
	if _, err := fs.f.ReadAt(buf, offset); err != nil {
		return extInode{}, err
	}

	inode := extInode{
		number: inodeNum,
		mode:   le16(buf, 0x00),
		flags:  le32(buf, 0x20),
		size:   uint64(le32(buf, 0x04)),
	}
	if len(buf) >= 112 {
		inode.size |= uint64(le32(buf, 0x6C)) << 32
	}
	copy(inode.iBlock[:], buf[0x28:0x28+60])
	return inode, nil
}

func (fs *extFS) readDirEntries(inode extInode) ([]extDirEntry, error) {
	data, err := fs.readAllData(inode)
	if err != nil {
		return nil, err
	}

	entries := make([]extDirEntry, 0, 32)
	for off := 0; off+8 <= len(data); {
		recLen := int(le16(data, off+4))
		if recLen < 8 || off+recLen > len(data) {
			return nil, fmt.Errorf("invalid directory record length at offset %d", off)
		}

		inodeNum := le32(data, off+0)
		nameLen := int(data[off+6])
		if inodeNum != 0 && nameLen > 0 && 8+nameLen <= recLen {
			name := string(data[off+8 : off+8+nameLen])
			entries = append(entries, extDirEntry{
				inode: inodeNum,
				name:  name,
			})
		}
		off += recLen
	}
	return entries, nil
}

func (fs *extFS) readAllData(inode extInode) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := fs.copyFileData(inode, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (fs *extFS) copyFileData(inode extInode, w io.Writer) (uint64, error) {
	runs, err := fs.collectRuns(inode)
	if err != nil {
		return 0, err
	}

	remaining := inode.size
	if remaining == 0 {
		return 0, nil
	}

	blockSize := fs.blockSize
	buf := make([]byte, int(blockSize))
	zero := make([]byte, int(blockSize))
	var logical uint64
	var written uint64

	writeChunk := func(chunk []byte) error {
		if len(chunk) == 0 {
			return nil
		}
		n, err := w.Write(chunk)
		written += uint64(n)
		if err != nil {
			return err
		}
		if n != len(chunk) {
			return io.ErrShortWrite
		}
		return nil
	}

	for _, run := range runs {
		for logical < run.logical && remaining > 0 {
			chunkLen := minU64(blockSize, remaining)
			if err := writeChunk(zero[:int(chunkLen)]); err != nil {
				return written, err
			}
			remaining -= chunkLen
			logical++
		}

		for i := uint64(0); i < run.count && remaining > 0; i++ {
			chunkLen := minU64(blockSize, remaining)
			if !run.initialized {
				if err := writeChunk(zero[:int(chunkLen)]); err != nil {
					return written, err
				}
			} else {
				if _, err := fs.f.ReadAt(buf, int64(run.physical+i)*int64(blockSize)); err != nil {
					return written, err
				}
				if err := writeChunk(buf[:int(chunkLen)]); err != nil {
					return written, err
				}
			}
			remaining -= chunkLen
			logical++
		}
	}

	for remaining > 0 {
		chunkLen := minU64(blockSize, remaining)
		if err := writeChunk(zero[:int(chunkLen)]); err != nil {
			return written, err
		}
		remaining -= chunkLen
	}

	return written, nil
}

func (fs *extFS) collectRuns(inode extInode) ([]blockRun, error) {
	totalBlocks := divCeil64(inode.size, fs.blockSize)
	if totalBlocks == 0 {
		return nil, nil
	}

	if inode.flags&extInodeFlagExtents != 0 {
		return fs.collectExtentRuns(inode.iBlock[:])
	}
	return fs.collectIndirectRuns(inode.iBlock[:], totalBlocks)
}

func (fs *extFS) collectExtentRuns(node []byte) ([]blockRun, error) {
	if len(node) < 12 {
		return nil, fmt.Errorf("short extent header")
	}
	if le16(node, 0) != extExtentMagic {
		return nil, fmt.Errorf("invalid extent header")
	}

	entries := int(le16(node, 2))
	depth := int(le16(node, 6))
	if entries < 0 || 12+entries*12 > len(node) {
		return nil, fmt.Errorf("invalid extent entry count")
	}

	runs := make([]blockRun, 0, entries)
	if depth == 0 {
		for i := 0; i < entries; i++ {
			off := 12 + i*12
			eeBlock := uint64(le32(node, off+0))
			rawLen := le16(node, off+4)
			initialized := true
			if rawLen > 32768 {
				initialized = false
				rawLen -= 32768
			}
			if rawLen == 0 {
				continue
			}
			start := (uint64(le16(node, off+6)) << 32) | uint64(le32(node, off+8))
			runs = appendRun(runs, eeBlock, start, uint64(rawLen), initialized)
		}
		return runs, nil
	}

	for i := 0; i < entries; i++ {
		off := 12 + i*12
		childBlock := (uint64(le16(node, off+8)) << 32) | uint64(le32(node, off+4))
		child := make([]byte, int(fs.blockSize))
		if _, err := fs.f.ReadAt(child, int64(childBlock)*int64(fs.blockSize)); err != nil {
			return nil, err
		}
		childRuns, err := fs.collectExtentRuns(child)
		if err != nil {
			return nil, err
		}
		runs = appendMergedRuns(runs, childRuns)
	}
	return runs, nil
}

func (fs *extFS) collectIndirectRuns(iBlock []byte, totalBlocks uint64) ([]blockRun, error) {
	runs := make([]blockRun, 0, totalBlocks)
	var logical uint64

	for i := 0; i < 12 && logical < totalBlocks; i++ {
		ptr := uint64(le32(iBlock, i*4))
		if ptr != 0 {
			runs = appendRun(runs, logical, ptr, 1, true)
		}
		logical++
	}

	if logical < totalBlocks {
		if err := fs.walkIndirect(le32(iBlock, 48), 1, &logical, totalBlocks, &runs); err != nil {
			return nil, err
		}
	}
	if logical < totalBlocks {
		if err := fs.walkIndirect(le32(iBlock, 52), 2, &logical, totalBlocks, &runs); err != nil {
			return nil, err
		}
	}
	if logical < totalBlocks {
		if err := fs.walkIndirect(le32(iBlock, 56), 3, &logical, totalBlocks, &runs); err != nil {
			return nil, err
		}
	}

	return runs, nil
}

func (fs *extFS) walkIndirect(block uint32, depth int, logical *uint64, totalBlocks uint64, runs *[]blockRun) error {
	if *logical >= totalBlocks {
		return nil
	}
	if block == 0 {
		*logical += minU64(indirectCapacity(uint64(fs.blockSize), depth), totalBlocks-*logical)
		return nil
	}

	buf := make([]byte, int(fs.blockSize))
	if _, err := fs.f.ReadAt(buf, int64(block)*int64(fs.blockSize)); err != nil {
		return err
	}

	entryCount := int(fs.blockSize / 4)
	for i := 0; i < entryCount && *logical < totalBlocks; i++ {
		ptr := le32(buf, i*4)
		if depth == 1 {
			if ptr != 0 {
				*runs = appendRun(*runs, *logical, uint64(ptr), 1, true)
			}
			*logical++
			continue
		}
		if err := fs.walkIndirect(ptr, depth-1, logical, totalBlocks, runs); err != nil {
			return err
		}
	}
	return nil
}

func indirectCapacity(blockSize uint64, depth int) uint64 {
	entries := blockSize / 4
	capacity := uint64(1)
	for i := 0; i < depth; i++ {
		capacity *= entries
	}
	return capacity
}

func appendMergedRuns(dst, src []blockRun) []blockRun {
	for _, run := range src {
		dst = appendRun(dst, run.logical, run.physical, run.count, run.initialized)
	}
	return dst
}

func appendRun(runs []blockRun, logical, physical, count uint64, initialized bool) []blockRun {
	if count == 0 {
		return runs
	}
	if len(runs) == 0 {
		return append(runs, blockRun{
			logical:     logical,
			physical:    physical,
			count:       count,
			initialized: initialized,
		})
	}

	last := &runs[len(runs)-1]
	if last.logical+last.count == logical && last.initialized == initialized {
		if !initialized || last.physical+last.count == physical {
			last.count += count
			return runs
		}
	}

	return append(runs, blockRun{
		logical:     logical,
		physical:    physical,
		count:       count,
		initialized: initialized,
	})
}

func (inode extInode) isRegular() bool {
	return inode.mode&extModeTypeMask == extModeReg
}

func (inode extInode) isDir() bool {
	return inode.mode&extModeTypeMask == extModeDir
}

func (inode extInode) isSymlink() bool {
	return inode.mode&extModeTypeMask == extModeLnk
}

func hashString(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}

func isRunPath(relPath string) bool {
	return relPath == "run" || strings.HasPrefix(relPath, "run/")
}

func divCeil64(a, b uint64) uint64 {
	if a == 0 {
		return 0
	}
	return 1 + (a-1)/b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func le16(buf []byte, off int) uint16 {
	return binary.LittleEndian.Uint16(buf[off:])
}

func le32(buf []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(buf[off:])
}
