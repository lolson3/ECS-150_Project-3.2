
# ECS 150 — Virtual File System (C)

A teaching-focused, POSIX‑style virtual file system implemented in C. The system stores files and directories inside a single **virtual disk image** and exposes a small, consistent API (in `libfs/`) along with command‑line utilities (in `apps/`) to format the image, inspect metadata, and perform common file operations.

## Table of Contents
- [Features](#features)
- [Build & Tooling](#build--tooling)
- [Quick Start](#quick-start)
- [Disk Layout](#disk-layout)
- [Testing & Debugging](#testing--debugging)
- [Limitations](#limitations)

## Features

- **Fixed‑size block device** stored as a single file
- **Superblock + free space bitmap + inode table + data blocks**
- **Directories & regular files** with hierarchical paths (`/a/b/c`)
- **Path resolution** with `.` and `..` handling
- **Create / read / write / truncate / unlink / mkdir / rmdir / readdir**
- **Atomic metadata updates** within a single process

## Build & Tooling

**Requirements**
- POSIX environment (Linux/macOS/WSL)
- `gcc`
- `make`

**Build everything**

Navigate to each directory and build the necessary files with the make command.
```bash
make
```

**Clean**

If you'd like to remove the built files, run the following in the respective directories.
```bash
make clean
```

## Quick Start

Create a 64 MiB virtual disk, format it, and perform a few operations:

```bash
# 1) Create an empty host file to act as the virtual disk
./fs_make.x <diskname> <data block count>     

# 2) Write to the virtual disk with a simple test
./simple_writer.x <diskname>

# 3) Read from the virtual disk with a simple test
./simple_reader.x <diskname>


## Library API (Overview)

Public headers under `libfs/` expose the primary interface. A typical usage for mounting a disk, creating a file, and writing to it looks like:

```c
#include "fs.h"

	int ret;
	char *diskname;
	int fd;
	char data[26] = "abcdefghijklmnopqrstuvwxyz";

	if (argc < 1) {
		printf("Usage: %s <diskimage>\n", argv[0]);
		exit(1);
	}

	/* Mount disk */
	diskname = argv[1];
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	/* Create file and open */
	ret = fs_create("myfile");
	ASSERT(!ret, "fs_create");

	fd = fs_open("myfile");
	ASSERT(fd >= 0, "fs_open");

	/* Write some data */
	ret = fs_write(fd, data, sizeof(data));
	ASSERT(ret == sizeof(data), "fs_write");

	/* Close file and unmount */
	fs_close(fd);
	fs_umount();

	return 0;
```

## Disk Layout

A common on‑disk (in‑image) structure:

```
[ Superblock ][ Free Bitmap ][ Inode Table ][ Data Blocks ... ]

Superblock:
  magic, version
  block_size
  total_blocks
  inode_table_start, inode_count
  data_region_start

Bitmap:
  1 bit per block (0=free, 1=used)

Inodes:
  type (file/dir), size, timestamps
  direct block pointers [...]
  (optional) single/double indirect pointers

Directories:
  sequence of (name, inode_id) entries
```

## Testing & Debugging

Please navigate to the scripts/README.md file to  find testing and debugging information.


## Limitations

- Single‑process mounting (no concurrency across processes).
- No POSIX permissions/ownership by default.
- No symlinks/hardlinks unless explicitly implemented.
- Maximum file size and path length bound by on‑disk constants.
