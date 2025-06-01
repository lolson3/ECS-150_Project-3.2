#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

/* Struct containing info about filesystem, representing the very first block in the disk */
typedef struct __attribute__((packed)) superblock {
	char signature[8]; // Offset 0x00, must be equal to "ECS150FS"
	uint16_t total_blocks; // Offset 0x08, total amount of blocks in virtual disk
	uint16_t root_index; // Offset 0x0A, root directory block index
	uint16_t start_index; // Offset 0x0C, data block start index
	uint16_t datablock_count; // Offset 0x0E, number of datablocks
	uint8_t fat_blocks; // Offset 0x10, number of blocks for FAT
	uint8_t  padding[4079]; // Offset 0x11, unused space
} superblock_t;

// Global instances of superblock for this disk, and count to see if it is mounted
static superblock_t sb;
static int is_mounted = 0;

/* Mounts a specified filesystem */
int fs_mount(const char *diskname)
{
	// Attempt to open disk, return -1 on failure
	if (block_disk_open(diskname) < 0) {
		return -1;
	}

	// Attempt to read disk with superblock as buffer, return -1 on failure
	if (block_read(0, &sb) < 0) {
		return -1;
	}

	// Check to see if signature is "ECS150FS", return -1 on failure
	if (memcmp(sb.signature, "ECS150FS", 8) != 0) {
		return -1;
	}

	// Check that total block count is accurate, return -1 on failure
	if (block_disk_count() != sb.total_blocks) {
		return -1;
	}

	// Mark disk as mounted
	is_mounted = 1;

	return 0;
}

/* Unmounts currently mounted filesystem */
int fs_umount(void)
{
	// Check if disk is mounted
	if (is_mounted == 0) {
		return -1;
	}

	// Attempt to close disk, return -1 on failure
	if (block_disk_close() < 0) {
		return -1;
	}

	// Mark disk as unmounted
	is_mounted = 0;

	return 0;
}

/* Prints info pertaining to the mounted filesystem found in the superblock */
int fs_info(void)
{
	uint8_t fat_buf[BLOCK_SIZE];
	int fat_free = 0;
	uint16_t fat_entry;

	uint8_t rdir_buf[BLOCK_SIZE];
	int rdir_free = 0;

	if (is_mounted == 0) {
		return -1;
	}

	// Calculates number of free fat blocks
	for (int i = 0; i < sb.fat_blocks; i++) {
    	if (block_read(1 + i, fat_buf) < 0) {
			return -1;
		}

		for (size_t j = 0; j < BLOCK_SIZE / sizeof(uint16_t); j++) {
			size_t index = i * (BLOCK_SIZE / 2) + j;
			if (index >= sb.datablock_count)
				break;

			memcpy(&fat_entry, &fat_buf[j * 2], sizeof(uint16_t));

			if (index != 0 && fat_entry == 0)
				fat_free++;
		}
	}

	// Calculates number of free root directory spaces
	if (block_read(sb.root_index, rdir_buf) < 0) {
		return -1;
	} 

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (rdir_buf[i * 32] == '\0') {
			rdir_free++;
		}
	}	

    printf("FS Info:\n");
    printf("total_blk_count=%u\n", sb.total_blocks);
    printf("fat_blk_count=%u\n", sb.fat_blocks);
    printf("rdir_blk=%u\n", sb.root_index);
    printf("data_blk=%u\n", sb.start_index);
    printf("data_blk_count=%u\n", sb.datablock_count);
    printf("fat_free_ratio=%u/%u\n", fat_free, sb.datablock_count);
    printf("rdir_free_ratio=%u/%u\n", rdir_free, FS_FILE_MAX_COUNT);

	return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}
