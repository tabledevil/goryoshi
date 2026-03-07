 
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>
#include <tsk/libtsk.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

// Skip the /run directory (since it produces many false positives)

#define ignore_run_dir 1

// Skip empty files or files with unallocated names (since they may produce false positives)

#define ignore_empty 1
#define ignore_unalloc 1

int hidden_files = 0;
char full_path[PATH_MAX];
char extract_path[PATH_MAX];
char *extract_dir;
char *mount_point;
struct dirent *dp;
DIR *dirp;

static void mkdir_p(const char *dir) {
    char path[PATH_MAX];
    char *c = NULL;

    snprintf(path, sizeof(path), "%s", dir);
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

TSK_WALK_RET_ENUM scan_callback(TSK_FS_FILE *file, const char *path, void *ptr) {

    if (file == NULL || file->name == NULL || file->name->name == NULL) {
        return TSK_WALK_CONT;
    }
    if (strcmp(file->name->name, ".") == 0 || strcmp(file->name->name, "..") == 0) {
        return TSK_WALK_CONT;
    }

    // Skip links, tsk virtual files/dirs and undefined files

    if (file->name->type == TSK_FS_NAME_TYPE_LNK || 
        file->name->type == TSK_FS_NAME_TYPE_UNDEF || 
        file->name->type == TSK_FS_NAME_TYPE_VIRT || 
        file->name->type == TSK_FS_NAME_TYPE_VIRT_DIR) {
        return TSK_WALK_CONT;
    }

    // Skip files with unallocted names

    #if ignore_unalloc != 0
    if (file->name->flags == TSK_FS_NAME_FLAG_UNALLOC) {
        return TSK_WALK_CONT;
    }
    #endif

    // Skip empty files

    #if ignore_empty != 0
    if (file->meta == NULL || file->meta->size <= 0) {
        return TSK_WALK_CONT;
    }
    #endif

    // Skip the /run directory

    #if ignore_run_dir != 0
    if (strcmp(path, "run") == 0 || strncmp(path, "run/", 4) == 0) {
        return TSK_WALK_CONT;
    }
    #endif

    sprintf(full_path, "%s%s", mount_point, path);

    dirp = opendir(full_path);
    int visible = 0;
    if (dirp == NULL) {
        // If parent path is not visible in userspace, treat children as hidden too.
        if (errno != ENOENT && errno != ENOTDIR) {
            printf("Failed to open directory: %s (errno=%d)\n", full_path, errno);
            return TSK_WALK_CONT;
        }
    } else {
        do {
            dp = readdir(dirp);
            if (dp != NULL) {
                if (strcmp(dp->d_name, file->name->name) == 0) {
                    visible = 1;
                    break;
                }
            }
        } while(dp != NULL);
        closedir(dirp);
    }
    if (visible) {
        return TSK_WALK_CONT;
    }

    printf("Hidden: %s%s (%li)\n", full_path, file->name->name, file->name->meta_addr);
    hidden_files += 1;

    sprintf(extract_path, "%s%s", extract_dir, path);

    if (file->name->type == TSK_FS_NAME_TYPE_DIR) {
        strcat(extract_path, file->name->name);
        mkdir_p(extract_path);
        printf("Created: %s\n", extract_path);
    }

    if (file->name->type == TSK_FS_NAME_TYPE_REG) {
        char buf[1024];
        ssize_t n;
        unsigned int offset;
        unsigned long long bytes_written = 0;
        FILE *fp;

        mkdir_p(extract_path);
        strcat(extract_path, file->name->name);

        fp = fopen(extract_path, "wb");
        offset = 0;
        while((n = tsk_fs_file_read(file, offset, buf, 1024, 0)) > 0) {
            // Write bytes verbatim; do not drop NUL bytes.
            size_t nw = fwrite(buf, 1, (size_t)n, fp);
            bytes_written += nw;
            if (nw != (size_t)n) {
                printf("Short write while extracting: %s\n", extract_path);
                break;
            }
            offset += (unsigned int)n;
        }
        fclose(fp);

        if (file->meta && bytes_written != (unsigned long long)file->meta->size) {
            printf("Warning: extracted size mismatch for %s (wrote=%llu expected=%llu)\n",
                extract_path, bytes_written, (unsigned long long)file->meta->size);
        }

        TSK_FS_HASH_RESULTS hashes;

        if (tsk_fs_file_hash_calc(file, &hashes, TSK_BASE_HASH_MD5 | TSK_BASE_HASH_SHA1) != 0) {
            printf("Failed to calculate hashes: %s%s\n", full_path, file->name->name);
        }

        printf("Extracted: %s | MD5=", extract_path);
        for (size_t i = 0; i < sizeof(hashes.md5_digest); i++) {
            printf("%02x", hashes.md5_digest[i]);
        }
        printf(" SHA1=");
        for (size_t i = 0; i < sizeof(hashes.sha1_digest); i++) {
            printf("%02x", hashes.sha1_digest[i]);
        }
        printf("\n");
    }

    return TSK_WALK_CONT;
}

int main(int argc, char *argv[]) {

    if (argc < 4) {
        printf("Usage: %s [volume] [mount point] [extract path]\nExample: %s /dev/sda1 / /evidence\n", argv[0], argv[0]);
        exit(-1);
    }

    if (geteuid() != 0) {
        printf("Root priviliges required to parse disk\n");
        exit(-1);
    }

    if (argv[2][strlen(argv[2]) - 1] != '/') {
        strcat(argv[2], "/");
    }

    if (argv[3][strlen(argv[3]) - 1] != '/') {
        strcat(argv[3], "/");
    }

    // Load volume or disk image

    TSK_IMG_INFO *disk_image = tsk_img_open_utf8_sing(argv[1], TSK_IMG_TYPE_DETECT, 0);

    if (disk_image == NULL) {
        printf("%s is not a valid volume or disk image\n", argv[1]);
        exit(-1);
    }

    // Open filesystem on volume / disk image

    TSK_FS_INFO *filesystem = tsk_fs_open_img(disk_image, 0, TSK_FS_TYPE_DETECT);

    if (filesystem == NULL) {
        printf("%s does not contain a supported filesystem\n", argv[1]);
        exit(-1);
    }

    printf("%s (%ldMB) -> %s (%li inodes)\n", argv[1], disk_image->size / 1000000, tsk_fs_type_toname(filesystem->ftype), filesystem->inum_count);

    mount_point = argv[2];
    extract_dir = argv[3];
    void *ptr = NULL;

    tsk_fs_dir_walk(filesystem, filesystem->root_inum, TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE | TSK_FS_DIR_WALK_FLAG_NOORPHAN, scan_callback, ptr);

    tsk_fs_close(filesystem);
    tsk_img_close(disk_image);

    if (hidden_files > 0) {
        printf("%i hidden file(s) found\nExtracted to: %s\n", hidden_files, argv[3]);
    } else {
        printf("No hidden files found\n");
    }

    exit(hidden_files);
}
