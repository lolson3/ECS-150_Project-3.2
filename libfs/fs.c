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

// Gloibal instance of file descriptor table and root directory table
static file_descriptor_t fd_table[FS_OPEN_MAX_COUNT];
static rd_entry_t rd_table[FS_FILE_MAX_COUNT];

#define FAT_EOC 0xFFFF	   // End of chain marker for FAT
#define RDIR_ENTRY_SIZE 32 // Size of each root directory entry

//  Offsets for root directory entries
#define FILENAME_OFFSET 0
#define FILESIZE_OFFSET 16
#define FIRST_BLOCK_OFFSET 20

// Helper function to read a 16-bit little-endian value from a byte buffer
static uint16_t read_le16(const uint8_t *buffer)
{
	return (uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8);
}

// Helper function to write a 16-bit value to a byte buffer in little-endian
static void write_le16(uint8_t *buffer, uint16_t value)
{
	buffer[0] = (uint8_t)(value & 0xFF);
	buffer[1] = (uint8_t)((value >> 8) & 0xFF);
}

// Helper function to read a 32-bit little-endian value from a byte buffer
static uint32_t read_le32(const uint8_t *buffer)
{
	return (uint32_t)buffer[0] |
		   ((uint32_t)buffer[1] << 8) |
		   ((uint32_t)buffer[2] << 16) |
		   ((uint32_t)buffer[3] << 24);
}
// Helper function to write a 32-bit value to a byte buffer in little-endian
static void write_le32(uint8_t *buffer, uint32_t value)
{
	buffer[0] = (uint8_t)(value & 0xFF);
	buffer[1] = (uint8_t)((value >> 8) & 0xFF);
	buffer[2] = (uint8_t)((value >> 16) & 0xFF);
	buffer[3] = (uint8_t)((value >> 24) & 0xFF);
}

// Helper to get a FAT entry from the in-memory FAT buffer
static uint16_t get_fat_entry_from_buffer(const uint8_t *fat_main_buffer, uint16_t index)
{
	// Each FAT entry is 2 bytes
	const uint8_t *p = fat_main_buffer + (index * 2);
	return read_le16(p);
}

// Helper to set a FAT entry in the in-memory FAT buffer
static void set_fat_entry_in_buffer(uint8_t *fat_main_buffer, uint16_t index, uint16_t value)
{
	uint8_t *p = fat_main_buffer + (index * 2);
	write_le16(p, value);
}

/* Mounts a specified filesystem */
int fs_mount(const char *diskname)
{
	// Attempt to open disk, return -1 on failure
	if (block_disk_open(diskname) < 0)
	{
		return -1;
	}

	// Attempt to read disk with superblock as buffer, return -1 on failure
	if (block_read(0, &sb) < 0)
	{
		return -1;
	}

	// Check to see if signature is "ECS150FS", return -1 on failure
	if (memcmp(sb.signature, "ECS150FS", 8) != 0)
	{
		return -1;
	}

	// Check that total block count is accurate, return -1 on failure
	if (block_disk_count() != sb.total_blocks)
	{
		return -1;
	}

	// Load root directory
	if (block_read(sb.root_index, rd_table) < 0)
	{
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
	if (is_mounted == 0)
	{
		return -1;
	}

	// Write back root directory
	if (block_write(sb.root_index, rd_table) < 0)
	{
		return -1;
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

	uint8_t rdir_buf[BLOCK_SIZE];
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

	// Calculates number of free root directory spaces
	if (block_read(sb.root_index, rdir_buf) < 0)
	{
		return -1;
	}

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (rdir_buf[i * 32] == '\0')
		{
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

	// Buffer to hold the root directory block
	uint8_t root_dir_block[BLOCK_SIZE];

	// Read the root directory block
	if (block_read(sb.root_index, root_dir_block) == -1)
	{
		return -1;
	}

	// Loop through the root directory entries to find an empty slot or check for existing filename
	int empty_slot = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		uint8_t *entry_ptr = root_dir_block + (i * RDIR_ENTRY_SIZE);

		// Check if filename is already taken and not empty
		if (entry_ptr[FILENAME_OFFSET] != '\0')
		{
			if (strncmp((char *)(entry_ptr + FILENAME_OFFSET), filename, FS_FILENAME_LEN) == 0)
			{
				return -1; // File already exists
			}
		}
		else
		{
			if (empty_slot == -1)
			{
				empty_slot = i; // Found an empty slot
			}
		}
	}

	if (empty_slot == -1)
	{
		return -1; // No empty slot found
	}

	// get a pointer to the start of the empty slot
	uint8_t *target_entry_ptr = root_dir_block + (empty_slot * RDIR_ENTRY_SIZE);

	strncpy((char *)(target_entry_ptr + FILENAME_OFFSET), filename, FS_FILENAME_LEN);

	if (strlen(filename) < FS_FILENAME_LEN - 1)
	{
		target_entry_ptr[FILENAME_OFFSET + FS_FILENAME_LEN - 1] = '\0';
	}

	uint16_t file_size = 0;
	target_entry_ptr[FILESIZE_OFFSET + 0] = (uint8_t)(file_size & 0xFF);
	target_entry_ptr[FILESIZE_OFFSET + 1] = (uint8_t)((file_size >> 8) & 0xFF);
	target_entry_ptr[FILESIZE_OFFSET + 2] = (uint8_t)((file_size >> 16) & 0xFF);
	target_entry_ptr[FILESIZE_OFFSET + 3] = (uint8_t)((file_size >> 24) & 0xFF);

	uint16_t first_block = FAT_EOC;
	target_entry_ptr[FIRST_BLOCK_OFFSET + 0] = (uint8_t)(first_block & 0xFF);
	target_entry_ptr[FIRST_BLOCK_OFFSET + 1] = (uint8_t)((first_block >> 8) & 0xFF);

	if (block_write(sb.root_index, root_dir_block) == -1)
	{
		return -1; // Failed to write back to root directory
	}

	return 0; // File created successfully
}

/* Delete a file with the given filename */
int fs_delete(const char *filename)
{
	if (!is_mounted || filename == NULL || strlen(filename) == 0 || strlen(filename) >= FS_FILENAME_LEN)
	{
		return -1; // Invalid parameters
	}

	uint8_t root_dir_block[BLOCK_SIZE];
	if (block_read(sb.root_index, root_dir_block) == -1)
	{
		return -1; // Failed to read root directory
	}

	int file_rdir_index = -1;
	uint8_t *file_entry_ptr = NULL;

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		uint8_t *current_entry = root_dir_block + (i * RDIR_ENTRY_SIZE);

		if (current_entry[FILENAME_OFFSET] != '\0' &&
			strncmp((char *)(current_entry + FILENAME_OFFSET), filename, FS_FILENAME_LEN) == 0)
		{
			file_rdir_index = i;
			file_entry_ptr = current_entry;
			break;
		}
	}

	if (file_rdir_index == -1)
	{
		return -1; // File not found
	}

	// Check if the file is open
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (fd_table[i].active && fd_table[i].entry_index == file_rdir_index)
		{
			return -1; // File is currently open
		}
	}

	uint16_t current_block = read_le16(file_entry_ptr + FIRST_BLOCK_OFFSET);

	if (current_block != FAT_EOC)
	{
		uint8_t fat_buf[BLOCK_SIZE];

		int fat_block_modified[sb.fat_blocks];
		for (int i = 0; i < sb.fat_blocks; i++)
		{
			fat_block_modified[i] = 0;
		}

		// Read all FAT blocks into buffer
		for (int i = 0; i < sb.fat_blocks; i++)
		{
			if (block_read(1 + i, fat_buf + (i * BLOCK_SIZE)) == -1)
			{
				return -1; // Failed to read FAT block
			}
		}

		while (current_block != FAT_EOC && current_block < sb.datablock_count)
		{
			uint16_t next_block = get_fat_entry_from_buffer(fat_buf, current_block);

			// Mark the FAT entry as free
			set_fat_entry_in_buffer(fat_buf, current_block, 0);

			int fat_block_array = (current_block * 2) / BLOCK_SIZE;
			if (fat_block_array < sb.fat_blocks)
			{
				fat_block_modified[fat_block_array] = 1;
			}

			// Find the next block in the chain
			if (next_block == current_block)
			{
				break; // Prevent infinite loop if next block points to itself
			}

			current_block = next_block;
		}

		for (int i = 0; i < sb.fat_blocks; i++)
		{
			if (fat_block_modified[i])
			{
				if (block_write(1 + i, fat_buf + (i * BLOCK_SIZE)) == -1)
				{
					return -1; // Failed to write FAT block
				}
			}
		}
	}

	// Mark the entry as free
	file_entry_ptr[FILENAME_OFFSET] = '\0';

	// Set file size to 0
	write_le32(file_entry_ptr + FILESIZE_OFFSET, 0);

	// set first block to FAT_EOC
	write_le16(file_entry_ptr + FIRST_BLOCK_OFFSET, FAT_EOC);

	// Write the modified root directory block back to disk
	if (block_write(sb.root_index, root_dir_block) == -1)
	{
		return -1; // Failed to write back to root directory
	}

	return 0; // File deleted successfully
}

/* List files in the filesystem */
int fs_ls(void)
{
	if (!is_mounted)
	{
		return -1;
	}

	uint8_t root_dir_block[BLOCK_SIZE];
	if (block_read(sb.root_index, root_dir_block) == -1)
	{
		return -1; // Failed to read root directory
	}

	// Print header
	printf("FS Ls:\n");

	// Iterate through all possible file entries
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		uint8_t *entry_ptr = root_dir_block + (i * RDIR_ENTRY_SIZE);

		// Skip if entry is empty (first byte is NULL)
		if (entry_ptr[FILENAME_OFFSET] == '\0')
		{
			continue;
		}

		// Get filename (null-terminated string)
		char filename[FS_FILENAME_LEN];
		memcpy(filename, entry_ptr + FILENAME_OFFSET, FS_FILENAME_LEN);
		filename[FS_FILENAME_LEN - 1] = '\0';

		// Get file size
		uint32_t file_size = read_le32(entry_ptr + FILESIZE_OFFSET);

		// Print file information
		printf("file: %s, size: %u, data_blk: %u\n",
			   filename,
			   file_size,
			   read_le16(entry_ptr + FIRST_BLOCK_OFFSET));
	}

	return 0;
}

/* Open file by giving it a file descriptor */
int fs_open(const char *filename)
{
	// FS_OPEN_MAX_COUNT 32

	// Check if disk is mounted
	if (is_mounted == 0)
	{
		return -1;
	}

	// Check filename is valid
	if (filename == NULL || strlen(filename) > 15)
	{
		return -1;
	}

	// Iterate through root directory, stop if there is a match
	int rd_index = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (strcmp(rd_table[i].filename, filename) == 0)
		{
			rd_index = i;
			break;
		}
	}

	// Check to see if rd_index has been changed. If not, file wasn't found.
	if (rd_index == -1)
	{
		return -1;
	}

	// Find inactive file descriptor and use it
	int fd = -1;
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++)
	{
		if (fd_table[i].active == 0)
		{
			fd_table[i].active = 1;
			fd_table[i].entry_index = rd_index;
			fd_table[i].offset = 0;
			fd = i;
			break;
		}
	}

	// Check to see if no file descriptor was found
	if (fd == -1)
	{
		return -1;
	}

	return fd;
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
	{
		return -1;
	}

	// Validate file descriptor
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].active)
	{
		return -1;
	}

	// Read root directory to get file info
	uint8_t root_dir_block[BLOCK_SIZE];
	if (block_read(sb.root_index, root_dir_block) == -1)
	{
		return -1;
	}

	// Get file entry pointer
	uint8_t *entry_ptr = root_dir_block + (fd_table[fd].entry_index * RDIR_ENTRY_SIZE);
	uint16_t first_block = read_le16(entry_ptr + FIRST_BLOCK_OFFSET);
	uint32_t file_size = read_le32(entry_ptr + FILESIZE_OFFSET);
	size_t current_offset = fd_table[fd].offset;

	// Read FAT blocks into memory
	uint8_t fat_buf[sb.fat_blocks * BLOCK_SIZE];
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		if (block_read(1 + i, fat_buf + (i * BLOCK_SIZE)) == -1)
		{
			return -1;
		}
	}

	// Calculate starting block and offset within block
	uint16_t current_block = first_block;
	size_t blocks_to_skip = current_offset / BLOCK_SIZE;
	size_t offset_in_block = current_offset % BLOCK_SIZE;

	// Skip to the correct block
	for (size_t i = 0; i < blocks_to_skip && current_block != FAT_EOC; i++)
	{
		current_block = get_fat_entry_from_buffer(fat_buf, current_block);
	}

	// If we need a new block chain
	if (current_block == FAT_EOC && count > 0)
	{
		// Find first free block
		uint16_t new_block = 0;
		for (new_block = 1; new_block < sb.datablock_count; new_block++)
		{
			if (get_fat_entry_from_buffer(fat_buf, new_block) == 0)
				break;
		}

		if (new_block >= sb.datablock_count)
		{
			return -1; // No free blocks available
		}

		// Update FAT and file entry if this is the first block
		if (first_block == FAT_EOC)
		{
			first_block = new_block;
			write_le16(entry_ptr + FIRST_BLOCK_OFFSET, new_block);
		}
		else
		{
			// Link the last block to the new block
			set_fat_entry_in_buffer(fat_buf, current_block, new_block);
		}
		current_block = new_block;
		set_fat_entry_in_buffer(fat_buf, new_block, FAT_EOC);
	}

	// Write data block by block
	size_t bytes_written = 0;
	uint8_t block_buf[BLOCK_SIZE];

	while (bytes_written < count && current_block != FAT_EOC)
	{
		// Read current block if we're not writing a full block
		if (offset_in_block > 0 || (count - bytes_written) < BLOCK_SIZE)
		{
			if (block_read(sb.start_index + current_block, block_buf) == -1)
			{
				break;
			}
		}

		// Calculate how much we can write in this block
		size_t block_space = BLOCK_SIZE - offset_in_block;
		size_t bytes_to_write = (count - bytes_written) < block_space ? (count - bytes_written) : block_space;

		// Copy data to block buffer
		memcpy(block_buf + offset_in_block,
			   (uint8_t *)buf + bytes_written,
			   bytes_to_write);

		// Write block back to disk
		if (block_write(sb.start_index + current_block, block_buf) == -1)
		{
			break;
		}

		bytes_written += bytes_to_write;
		offset_in_block = 0;

		// If we need another block
		if (bytes_written < count)
		{
			uint16_t next_block = get_fat_entry_from_buffer(fat_buf, current_block);
			if (next_block == FAT_EOC)
			{
				// Find a new block
				uint16_t new_block = 0;
				for (new_block = 1; new_block < sb.datablock_count; new_block++)
				{
					if (get_fat_entry_from_buffer(fat_buf, new_block) == 0)
						break;
				}

				if (new_block >= sb.datablock_count)
				{
					break; // No more free blocks
				}

				// Update FAT
				set_fat_entry_in_buffer(fat_buf, current_block, new_block);
				set_fat_entry_in_buffer(fat_buf, new_block, FAT_EOC);
				current_block = new_block;
			}
			else
			{
				current_block = next_block;
			}
		}
	}

	// Update FAT blocks
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		if (block_write(1 + i, fat_buf + (i * BLOCK_SIZE)) == -1)
		{
			return -1;
		}
	}

	// Update file size if necessary
	size_t new_file_size = current_offset + bytes_written;
	if (new_file_size > file_size)
	{
		write_le32(entry_ptr + FILESIZE_OFFSET, new_file_size);
		if (block_write(sb.root_index, root_dir_block) == -1)
		{
			return -1;
		}
	}

	// Update file offset
	fd_table[fd].offset += bytes_written;

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

	// Read root directory to get file info
	uint8_t root_dir_block[BLOCK_SIZE];
	if (block_read(sb.root_index, root_dir_block) == -1)
	{
		return -1;
	}

	// Get file entry pointer
	uint8_t *entry_ptr = root_dir_block + (fd_table[fd].entry_index * RDIR_ENTRY_SIZE);
	uint16_t first_block = read_le16(entry_ptr + FIRST_BLOCK_OFFSET);
	uint32_t file_size = read_le32(entry_ptr + FILESIZE_OFFSET);
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

	// Read FAT blocks into memory
	uint8_t fat_buf[sb.fat_blocks * BLOCK_SIZE];
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		if (block_read(1 + i, fat_buf + (i * BLOCK_SIZE)) == -1)
		{
			return -1;
		}
	}

	// Calculate starting block and offset within block
	uint16_t current_block = first_block;
	size_t blocks_to_skip = current_offset / BLOCK_SIZE;
	size_t offset_in_block = current_offset % BLOCK_SIZE;

	// Skip to the correct block
	for (size_t i = 0; i < blocks_to_skip && current_block != FAT_EOC; i++)
	{
		current_block = get_fat_entry_from_buffer(fat_buf, current_block);
	}

	// Read data block by block
	size_t bytes_read = 0;
	uint8_t block_buf[BLOCK_SIZE];

	while (bytes_read < count && current_block != FAT_EOC)
	{
		// Read current block
		if (block_read(sb.start_index + current_block, block_buf) == -1)
		{
			break;
		}

		// Calculate how much we can read from this block
		size_t block_space = BLOCK_SIZE - offset_in_block;
		size_t bytes_to_read = (count - bytes_read) < block_space ? (count - bytes_read) : block_space;

		// Copy data from block buffer to user buffer
		memcpy((uint8_t *)buf + bytes_read,
			   block_buf + offset_in_block,
			   bytes_to_read);

		bytes_read += bytes_to_read;
		offset_in_block = 0;

		// Move to next block if we need more data
		if (bytes_read < count)
		{
			current_block = get_fat_entry_from_buffer(fat_buf, current_block);
		}
	}

	// Update file offset
	fd_table[fd].offset += bytes_read;

	return bytes_read;
}
