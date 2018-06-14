
#ifndef P5_H
#define P5_H

#define MAX_FILE_NAME_LENGTH 50
#define MAX_OPEN_FILES 10

/* file API */
extern int my_open (char * path);
extern int my_creat (char * path);
extern int my_read (int fd, void * buf, int count);
extern int my_write (int fd, void * buf, int count);
extern int my_close (int fd);

extern int my_remove (char * path);
extern int my_rename (char * old, char * new);
extern int my_mkdir (char * path);
extern int my_rmdir (char * path);

extern void my_mkfs ();

#define BLOCKCOUNT 250000			/* total number of blocks */
#define BLOCKSIZE 1024				/* size of each block */
#define BMPSIZE (BLOCKCOUNT / 8)	/* 31250 bytes for bitmap, 32 blocks */
#define SIGNATURE 0x2018			/* magic number to id filesystem */
/*
	We reserve the first 512KB for the filesystem.
	Block 0, holds signature.
	Block 1~32, holds block bitmap.
	Block 33~450, holds inodes.
	Block 511, inode bitmap.
	Each block contains 12 inode structures.
	Directory file only store the index number of inodes of files contained within.
*/
#define BLOCKBITMAP 1
#define INODEBITMAP 511
#define RESERVEDBLOCKS 512
#define RESERVEDSPACE (512 * 1024)	/* 512KB reserved space */
#define DATABLOCK 512
#define ROOTINODE 33
#define MAX_INODE_CNT 5016
#define INODE_BMP_SIZE (MAX_INODE_CNT / 8)
#define DATA_BMP_START_BYTE (RESERVEDBLOCKS / 8)
#define ROOTINDEX (ROOTINODE * BLOCKSIZE)
#define FS_FILE 0
#define FS_DIRECTORY 1

#define PTRPERBLOCK (BLOCKSIZE / sizeof(int))

/* not used in any declaration, just a reminder that each block is 1KB */
/* and may be useful inside the code. */
typedef char block [BLOCKSIZE];

typedef struct {		/* 80 bytes in size, total 5000 inodes of 417 blocks */
	int size;			/* total size of the file */
	int index;			/* starting address of inode */
	int primary_ptr;	/* capacity up to 256KB */
	int secondary_ptr;	/* block of primary_ptr, capacity up to 64MB */
	char name[50];		/* file name */
	char type;			/* 0 for file, 1 for directory */
	char nlink;			/* number of hard links */
	char uid;
	char gid;
	int blocks;			/* number of blocks */
	unsigned int attributes;
} inode, *pinode;

#define INODE_PER_BLOCK (BLOCKSIZE / sizeof(inode))

typedef struct {
	char name[50];
	int index;
} dentry, *pdentry;

/* provided by the lower layer */
extern int dev_open ();
extern int read_block (int block_num, char * block);
extern int write_block (int block_num, char * block);
extern void my_closefs();

#endif /* P5_H */

