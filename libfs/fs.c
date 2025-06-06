#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

/* Struct containing info about filesystem, representing the very first block in the disk */
typedef struct __attribute__((packed)) superblock
{
	char signature[8];		  // Offset 0x00, must be equal to "ECS150FS"
	uint16_t total_blocks;	  // Offset 0x08, total amount of blocks in virtual disk
	uint16_t root_index;	  // Offset 0x0A, root directory block index
	uint16_t start_index;	  // Offset 0x0C, data block start index
	uint16_t datablock_count; // Offset 0x0E, number of datablocks
	uint8_t fat_blocks;		  // Offset 0x10, number of blocks for FAT
	uint8_t padding[4079];	  // Offset 0x11, unused space
} superblock_t;

/* Struct containing file descriptor info */
typedef struct file_descriptor
{
	int active;		 // 0 or 1
	int entry_index; // Root directory entry index
	uint32_t offset; // Current read/write position
} file_descriptor_t;

/* Struct containing root directory entry info */
typedef struct __attribute__((packed)) rd_entry
{
	char filename[16];
	uint32_t size;
	uint16_t index;
	uint8_t padding[10];
} rd_entry_t;

// Global instances of superblock for this disk, and count to see if it is mounted
static superblock_t sb;
static int is_mounted = 0;

// Global instance of file descriptor table and root directory table
static file_descriptor_t fd_table[FS_OPEN_MAX_COUNT];
static rd_entry_t rd_table[FS_FILE_MAX_COUNT];

// Global instance of fat buffer
static uint16_t *fat_buffer = NULL;

#define FAT_EOC 0xFFFF	   // End of chain marker for FAT
#define RDIR_ENTRY_SIZE 32 // Size of each root directory entry

//  Offsets for root directory entries
#define FILENAME_OFFSET 0
#define FILESIZE_OFFSET 16
#define FIRST_BLOCK_OFFSET 20

/* Mounts a specified filesystem */
int fs_mount(const char *diskname)
{
	// Check if disk is already mounted
	if (is_mounted) {
		return -1;
	}

	// Attempt to open disk, return -1 on failure
	if (block_disk_open(diskname) < 0)
	{
		return -1;
	}

	// Attempt to read disk with superblock as buffer, return -1 on failure
	if (block_read(0, &sb) < 0)
	{
		block_disk_close();
		return -1;
	}

	// Check to see if signature is "ECS150FS" and that total block count is accurate, return -1 on failure
	if (memcmp(sb.signature, "ECS150FS", 8) != 0 || block_disk_count() != sb.total_blocks)
	{
		block_disk_close();
		return -1;
	}

	// Load root directory into memory
	if (block_read(sb.root_index, rd_table) < 0)
	{
		block_disk_close();
		return -1;
	}

	// Allocate FAT buffer
	if (fat_buffer != NULL)
	{
		free(fat_buffer);
		fat_buffer = NULL;
	}

	// Set size of fat buffer
	fat_buffer = malloc(sb.datablock_count * BLOCK_SIZE);
	if (fat_buffer == NULL) {
		block_disk_close();
		return -1;
	}

	// Load FAT blocks into memory
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		if (block_read(1 + i, (uint8_t *)fat_buffer + i * BLOCK_SIZE) < 0)
		{
			free(fat_buffer);
			fat_buffer = NULL;
			block_disk_close();
			return -1;
		}
	}

	// Mark disk as mounted
	is_mounted = 1;

	return 0;
}

/* Unmounts currently mounted filesystem */
int fs_umount(void)
{
	// Check if disk is mounted
	if (is_mounted == 0)
	{
		return -1;
	}

	// Write back root directory
	if (block_write(sb.root_index, rd_table) < 0)
	{
		return -1;
	}

	// Write back FAT
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		if (block_write(1 + i, (uint8_t *)fat_buffer + i * BLOCK_SIZE) < 0)
			return -1;
	}

	// Free memory used for fat buffer
	if (fat_buffer != NULL) {
		free(fat_buffer);
		fat_buffer = NULL;
	}

	// Attempt to close disk, return -1 on failure
	if (block_disk_close() < 0)
	{
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

	int rdir_free = 0;

	if (is_mounted == 0)
	{
		return -1;
	}

	// Calculates number of free fat blocks
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		if (block_read(1 + i, fat_buf) < 0)
		{
			return -1;
		}

		for (size_t j = 0; j < BLOCK_SIZE / sizeof(uint16_t); j++)
		{
			size_t index = i * (BLOCK_SIZE / 2) + j;
			if (index >= sb.datablock_count)
				break;

			memcpy(&fat_entry, &fat_buf[j * 2], sizeof(uint16_t));

			if (index != 0 && fat_entry == 0)
				fat_free++;
		}
	}

	// Calculates the number of free root directory spaces
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (rd_table[i].filename[0] == '\0') {
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

/* Create a file with the given filename */
int fs_create(const char *filename)
{
	// Check if filesystem is mounted and filename is valid
	if (!is_mounted || filename == NULL || strlen(filename) >= FS_FILENAME_LEN)
	{
		return -1;
	}

	// Checks for duplicate filename
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strcmp(rd_table[i].filename, filename) == 0)
            return -1;
    }

	// Loop through the root directory entries to find an empty slot or check for existing filename
	int free_entry = -1;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (rd_table[i].filename[0] == '\0') {
            free_entry = i;
            break;
        }
    }

	// Error checking for 0 free entries
	if (free_entry == -1) {
        return -1;
	}

	// Set values in root directory for new file
    strncpy(rd_table[free_entry].filename, filename, FS_FILENAME_LEN);
    rd_table[free_entry].filename[FS_FILENAME_LEN - 1] = '\0';
    rd_table[free_entry].size = 0;
    rd_table[free_entry].index = FAT_EOC;
    memset(rd_table[free_entry].padding, 0, sizeof(rd_table[free_entry].padding));

	// Ensures updated root directory in memory matches root directory in storage
    if (block_write(sb.root_index, rd_table) < 0)
        return -1;

    return 0;
}

/* Delete a file with the given filename */
int fs_delete(const char *filename)
{
	// Check if filesystem is mounted and filename is valid
	if (!is_mounted || filename == NULL || strlen(filename) == 0 || strlen(filename) >= FS_FILENAME_LEN)
	{
		return -1;
	}

	// Search for the file in the root directory
	int file_index = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (strcmp(rd_table[i].filename, filename) == 0)
		{
			file_index = i;
			break;
		}
	}

	if (file_index == -1)
	{
		return -1; // File not found
	}

	// Check if the file is currently open
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++)
	{
		if (fd_table[i].active && fd_table[i].entry_index == file_index)
		{
			return -1; // File is currently open
		}
	}

	// Free all FAT blocks associated with the file
	uint16_t current_block = rd_table[file_index].index;

	while (current_block != FAT_EOC)
	{
		uint16_t next_block = fat_buffer[current_block];
		fat_buffer[current_block] = 0; // Mark the current FAT entry as free
		current_block = next_block;
	}

	// Clear the root directory entry
	rd_table[file_index].filename[0] = '\0';
	rd_table[file_index].size = 0;
	rd_table[file_index].index = FAT_EOC;
	memset(rd_table[file_index].padding, 0, sizeof(rd_table[file_index].padding));

	// Write updated FAT back to disk
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		if (block_write(1 + i, ((uint8_t*)fat_buffer) + i * BLOCK_SIZE) == -1)
		{
			return -1;
		}
	}

	// Write updated root directory back to disk
	if (block_write(sb.root_index, rd_table) == -1)
	{
		return -1;
	}

	return 0; // File deleted successfully
}

/* List files in the filesystem */
int fs_ls(void)
{
	// Check if filesystem is mounted
	if (!is_mounted)
	{
		return -1;
	}

	// Print header
	printf("FS Ls:\n");

	// Iterate through all possible file entries in rd_table
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		// Skip empty entries (first byte of filename is NULL)
		if (rd_table[i].filename[0] == '\0')
		{
			continue;
		}

		// Print file information directly from struct
		printf("file: %s, size: %u, data_blk: %u\n",
			   rd_table[i].filename,
			   rd_table[i].size,
			   rd_table[i].index);
	}

	return 0;
}

/* Open file by giving it a file descriptor */
int fs_open(const char *filename)
{
	// Check if filesystem is mounted
	if (!is_mounted)
		return -1;

	// Validate filename
	if (filename == NULL || strlen(filename) == 0 || strlen(filename) >= FS_FILENAME_LEN)
		return -1;

	// Search for the file in the in-memory root directory table
	int rd_index = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (strcmp(rd_table[i].filename, filename) == 0)
		{
			rd_index = i;
			break;
		}
	}

	// If file not found, return error
	if (rd_index == -1)
		return -1;

	// Search for a free file descriptor slot
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++)
	{
		if (!fd_table[i].active)
		{
			fd_table[i].active = 1;
			fd_table[i].entry_index = rd_index;
			fd_table[i].offset = 0;
			return i;
		}
	}

	// No free file descriptor available
	return -1;
}

/* Close file descriptor */
int fs_close(int fd)
{
	if (is_mounted == 0)
	{
		return -1;
	}

	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
	{
		return -1;
	}

	// If file descriptor is active, reset it
	if (fd_table[fd].active != 0)
	{
		fd_table[fd].entry_index = -1;
		fd_table[fd].offset = 0;
		fd_table[fd].active = 0;
	}
	else
	{
		return -1;
	}

	return 0;
}

/* Get size of a file */
int fs_stat(int fd)
{
	if (is_mounted == 0)
	{
		return -1;
	}

	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
	{
		return -1;
	}

	if (fd_table[fd].active == 0)
	{
		return -1;
	}

	// Get entry and return the size found in the root directory
	int entry = fd_table[fd].entry_index;
	return rd_table[entry].size;
}

/* Change read/write position in file */
int fs_lseek(int fd, size_t offset)
{
	// General error checking
	if (is_mounted == 0)
	{
		return -1;
	}

	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
	{
		return -1;
	}

	if (fd_table[fd].active == 0)
	{
		return -1;
	}

	// Get entry index in file descriptor table
	int entry = fd_table[fd].entry_index;

	// Check for offset exceeding sizes of file
	if (offset > rd_table[entry].size)
	{
		return -1;
	}

	// Set new offset
	fd_table[fd].offset = offset;

	return 0;
}

/* Write to file */
int fs_write(int fd, void *buf, size_t count)
{
	// Input validation
	if (!is_mounted || !buf)
		return -1;

	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].active)
		return -1;

	int entry_index = fd_table[fd].entry_index;
	uint32_t file_size = rd_table[entry_index].size;
	uint32_t current_offset = fd_table[fd].offset;

	// Don't allow writing beyond maximum file size (optional, depending on your spec)
	if (current_offset + count > BLOCK_SIZE * sb.datablock_count)
		count = BLOCK_SIZE * sb.datablock_count - current_offset;

	// Calculate how many bytes we can actually write
	if (count == 0)
		return 0;

	// Walk FAT chain to current block (or allocate blocks as needed)
	uint16_t current_block = rd_table[entry_index].index;

	// If file has no blocks yet, allocate the first block
	if (current_block == FAT_EOC)
	{
		// Find a free block
		int new_block = -1;
		for (int i = 0; i < sb.datablock_count; i++)
		{
			if (fat_buffer[i] == 0)
			{
				new_block = i;
				break;
			}
		}

		if (new_block == -1)
			return 0; // Disk full

		// Allocate new block
		fat_buffer[new_block] = FAT_EOC;
		rd_table[entry_index].index = new_block;
		current_block = new_block;
	}

	// Skip blocks according to current offset
	uint32_t blocks_to_skip = current_offset / BLOCK_SIZE;
	uint32_t offset_in_block = current_offset % BLOCK_SIZE;

	for (uint32_t i = 0; i < blocks_to_skip; i++)
	{
		if (fat_buffer[current_block] == FAT_EOC)
		{
			// Allocate new block if needed
			int new_block = -1;
			for (int j = 0; j < sb.datablock_count; j++)
			{
				if (fat_buffer[j] == 0)
				{
					new_block = j;
					break;
				}
			}

			if (new_block == -1)
				return i * BLOCK_SIZE; // Partial write if disk full

			fat_buffer[current_block] = new_block;
			fat_buffer[new_block] = FAT_EOC;
		}

		current_block = fat_buffer[current_block];
	}

	// Now perform the actual writing
	size_t bytes_written = 0;
	uint8_t block_buf[BLOCK_SIZE];

	while (bytes_written < count)
	{
		// Read current block
		if (block_read(sb.start_index + current_block, block_buf) == -1)
			break;

		// Calculate how much to write into this block
		size_t block_space = BLOCK_SIZE - offset_in_block;
		size_t write_now = (count - bytes_written < block_space) ? (count - bytes_written) : block_space;

		memcpy(block_buf + offset_in_block, (uint8_t *)buf + bytes_written, write_now);

		if (block_write(sb.start_index + current_block, block_buf) == -1)
			break;

		bytes_written += write_now;
		offset_in_block = 0;

		if (bytes_written < count)
		{
			// Need to move to next block
			if (fat_buffer[current_block] == FAT_EOC)
			{
				// Allocate new block
				int new_block = -1;
				for (int j = 0; j < sb.datablock_count; j++)
				{
					if (fat_buffer[j] == 0)
					{
						new_block = j;
						break;
					}
				}

				if (new_block == -1)
					break;

				fat_buffer[current_block] = new_block;
				fat_buffer[new_block] = FAT_EOC;
			}

			current_block = fat_buffer[current_block];
		}
	}

	// Update file offset
	fd_table[fd].offset += bytes_written;

	// Update file size if needed
	if (fd_table[fd].offset > file_size)
		rd_table[entry_index].size = fd_table[fd].offset;

	return bytes_written;
}


/* Read from file */
int fs_read(int fd, void *buf, size_t count)
{
	// Input validation
	if (!is_mounted || !buf)
	{
		return -1;
	}

	// Validate file descriptor
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].active)
	{
		return -1;
	}

	// Get file entry directly from in-memory root directory
	int entry_index = fd_table[fd].entry_index;
	uint16_t first_block = rd_table[entry_index].index;
	uint32_t file_size = rd_table[entry_index].size;
	size_t current_offset = fd_table[fd].offset;

	// Check if we're trying to read past EOF
	if (current_offset >= file_size)
	{
		return 0;
	}

	// Adjust count if it would read past EOF
	if (current_offset + count > file_size)
	{
		count = file_size - current_offset;
	}

	// Calculate starting block and offset within block
	uint16_t current_block = first_block;
	size_t blocks_to_skip = current_offset / BLOCK_SIZE;
	size_t offset_in_block = current_offset % BLOCK_SIZE;

	// Walk FAT to the correct starting block
	for (size_t i = 0; i < blocks_to_skip && current_block != FAT_EOC; i++)
	{
		current_block = fat_buffer[current_block];
	}

	// Read data block by block
	size_t bytes_read = 0;
	uint8_t block_buf[BLOCK_SIZE];

	while (bytes_read < count && current_block != FAT_EOC)
	{
		// Read current data block from disk
		if (block_read(sb.start_index + current_block, block_buf) == -1)
		{
			break;
		}

		// Calculate how much to read from this block
		size_t block_space = BLOCK_SIZE - offset_in_block;
		size_t bytes_to_read = (count - bytes_read < block_space) ? (count - bytes_read) : block_space;

		// Copy data from block buffer to user buffer
		memcpy((uint8_t *)buf + bytes_read, block_buf + offset_in_block, bytes_to_read);

		bytes_read += bytes_to_read;
		offset_in_block = 0; // Only applies for first block

		// Move to next block if more data is needed
		if (bytes_read < count)
		{
			current_block = fat_buffer[current_block];
		}
	}

	// Update file offset
	fd_table[fd].offset += bytes_read;

	return bytes_read;
}