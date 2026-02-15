//go:build linux && cgo

package tsk

/*
#cgo LDFLAGS: -ltsk

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <tsk/libtsk.h>

typedef struct {
	int ignore_run;
	int ignore_empty;
	int ignore_unalloc;

	int hidden_files;

	char mount_point[PATH_MAX];
	char extract_dir[PATH_MAX];
} scan_ctx_t;

static void mkdir_p(const char *dir) {
	char path[PATH_MAX];
	char *c = NULL;

	snprintf(path, sizeof(path), "%s", dir);
	if (path[0] == 0) return;
	if (path[strlen(path) - 1] == '/') {
		path[strlen(path) - 1] = 0;
	}
	for (c = path + 1; *c; c++) {
		if (*c == '/') {
			*c = 0;
			mkdir(path, S_IRWXU);
			*c = '/';
		}
	}
	mkdir(path, S_IRWXU);
}

static int path_starts_with_run(const char *path) {
	// TSK callback path is relative without leading '/'. Examples: "" , "home/user/", "run/".
	return (path != NULL && strncmp(path, "run", 3) == 0);
}

static TSK_WALK_RET_ENUM scan_callback(TSK_FS_FILE *file, const char *path, void *ptr) {
	scan_ctx_t *ctx = (scan_ctx_t*)ptr;

	if (file == NULL || file->name == NULL || file->name->name == NULL) {
		return TSK_WALK_CONT;
	}

	// Skip links, virtuals and undefined.
	if (file->name->type == TSK_FS_NAME_TYPE_LNK ||
		file->name->type == TSK_FS_NAME_TYPE_UNDEF ||
		file->name->type == TSK_FS_NAME_TYPE_VIRT ||
		file->name->type == TSK_FS_NAME_TYPE_VIRT_DIR) {
		return TSK_WALK_CONT;
	}

	if (ctx->ignore_unalloc && file->name->flags == TSK_FS_NAME_FLAG_UNALLOC) {
		return TSK_WALK_CONT;
	}

	if (ctx->ignore_run && path_starts_with_run(path)) {
		return TSK_WALK_CONT;
	}

	// Skip empty regular files (dirs have size too, but we only apply to regular files).
	if (ctx->ignore_empty && file->name->type == TSK_FS_NAME_TYPE_REG) {
		if (file->meta == NULL || file->meta->size <= 0) {
			return TSK_WALK_CONT;
		}
	}

	char dir_path[PATH_MAX];
	snprintf(dir_path, sizeof(dir_path), "%s%s", ctx->mount_point, (path ? path : ""));

	DIR *dirp = opendir(dir_path);
	if (dirp == NULL) {
		printf("Failed to open directory: %s\n", dir_path);
		return TSK_WALK_CONT;
	}

	struct dirent *dp;
	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, file->name->name) == 0) {
			closedir(dirp);
			return TSK_WALK_CONT;
		}
	}
	closedir(dirp);

	// Hidden on-disk vs userspace view.
	printf("Hidden: %s%s (%li)\n", dir_path, file->name->name, file->name->meta_addr);
	ctx->hidden_files += 1;

	char out_base[PATH_MAX];
	snprintf(out_base, sizeof(out_base), "%s%s", ctx->extract_dir, (path ? path : ""));

	if (file->name->type == TSK_FS_NAME_TYPE_DIR) {
		char out_dir[PATH_MAX];
		snprintf(out_dir, sizeof(out_dir), "%s%s", out_base, file->name->name);
		mkdir_p(out_dir);
		printf("Created: %s\n", out_dir);
		return TSK_WALK_CONT;
	}

	if (file->name->type == TSK_FS_NAME_TYPE_REG) {
		// Ensure parent dirs exist.
		mkdir_p(out_base);

		char out_path[PATH_MAX];
		snprintf(out_path, sizeof(out_path), "%s%s", out_base, file->name->name);

		FILE *fp = fopen(out_path, "wb");
		if (fp == NULL) {
			printf("Failed to create: %s\n", out_path);
			return TSK_WALK_CONT;
		}

		char buf[8192];
		TSK_OFF_T offset = 0;
		while (1) {
			ssize_t n = tsk_fs_file_read(file, offset, buf, sizeof(buf), 0);
			if (n <= 0) break;
			// IMPORTANT: write bytes verbatim; do not drop NUL bytes.
			fwrite(buf, 1, (size_t)n, fp);
			offset += (TSK_OFF_T)n;
		}
		fclose(fp);

		TSK_FS_HASH_RESULTS hashes;
		if (tsk_fs_file_hash_calc(file, &hashes, TSK_BASE_HASH_MD5 | TSK_BASE_HASH_SHA1) != 0) {
			printf("Failed to calculate hashes: %s%s\n", dir_path, file->name->name);
			return TSK_WALK_CONT;
		}

		printf("Extracted: %s | MD5=", out_path);
		for (int i = 0; i < TSK_MD5_DIGEST_LENGTH; i++) {
			printf("%02x", hashes.md5_digest[i]);
		}
		printf(" SHA1=");
		for (int i = 0; i < TSK_SHA_DIGEST_LENGTH; i++) {
			printf("%02x", hashes.sha1_digest[i]);
		}
		printf("\n");
	}

	return TSK_WALK_CONT;
}

static void ensure_trailing_slash(char *s, size_t cap) {
	size_t n = strlen(s);
	if (n == 0) return;
	if (s[n-1] == '/') return;
	if (n+1 >= cap) return;
	s[n] = '/';
	s[n+1] = 0;
}

int ryoshi_scan(const char *volume, const char *mount_point, const char *extract_dir,
				int ignore_run, int ignore_empty, int ignore_unalloc,
				int *out_hidden) {
	if (out_hidden) *out_hidden = 0;
	if (volume == NULL || mount_point == NULL || extract_dir == NULL) return -1;

	scan_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ignore_run = ignore_run;
	ctx.ignore_empty = ignore_empty;
	ctx.ignore_unalloc = ignore_unalloc;

	snprintf(ctx.mount_point, sizeof(ctx.mount_point), "%s", mount_point);
	snprintf(ctx.extract_dir, sizeof(ctx.extract_dir), "%s", extract_dir);
	ensure_trailing_slash(ctx.mount_point, sizeof(ctx.mount_point));
	ensure_trailing_slash(ctx.extract_dir, sizeof(ctx.extract_dir));

	TSK_IMG_INFO *img = tsk_img_open_utf8_sing(volume, TSK_IMG_TYPE_DETECT, 0);
	if (img == NULL) {
		printf("%s is not a valid volume or disk image\n", volume);
		return -2;
	}

	TSK_FS_INFO *fs = tsk_fs_open_img(img, 0, TSK_FS_TYPE_DETECT);
	if (fs == NULL) {
		printf("%s does not contain a supported filesystem\n", volume);
		tsk_img_close(img);
		return -3;
	}

	printf("%s (%ldMB) -> %s (%li inodes)\n",
		   volume, (long)(img->size / 1000000),
		   tsk_fs_type_toname(fs->ftype), (long)fs->inum_count);

	tsk_fs_dir_walk(fs, fs->root_inum,
					TSK_FS_DIR_WALK_FLAG_RECURSE | TSK_FS_DIR_WALK_FLAG_NOORPHAN,
					scan_callback, &ctx);

	tsk_fs_close(fs);
	tsk_img_close(img);

	if (out_hidden) *out_hidden = ctx.hidden_files;

	if (ctx.hidden_files > 0) {
		printf("%i hidden file(s) found\nExtracted to: %s\n", ctx.hidden_files, ctx.extract_dir);
	} else {
		printf("No hidden files found\n");
	}

	return 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func Scan(volume, mountPoint, extractPath string, opts ScanOptions) (int, error) {
	cVol := C.CString(volume)
	cMP := C.CString(mountPoint)
	cEx := C.CString(extractPath)
	defer C.free(unsafe.Pointer(cVol))
	defer C.free(unsafe.Pointer(cMP))
	defer C.free(unsafe.Pointer(cEx))

	var hidden C.int
	rc := C.ryoshi_scan(
		cVol, cMP, cEx,
		boolToInt(opts.IgnoreRunDir),
		boolToInt(opts.IgnoreEmpty),
		boolToInt(opts.IgnoreUnalloc),
		&hidden,
	)
	if rc != 0 {
		return int(hidden), fmt.Errorf("libtsk scan failed (rc=%d)", int(rc))
	}
	return int(hidden), nil
}

func boolToInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}
