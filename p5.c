#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "p5.h"

/* maintain free blocks*/
static char data_bitmap[BMPSIZE];
/* maintain inode space */
static char inode_bitmap[BLOCKSIZE];
/* maintain open files */
static inode* open_inode[MAX_OPEN_FILES];
static int seek_ptr[MAX_OPEN_FILES];
static int free_fd = 0;

/* print a block */
static void dbg_print_block(block blk) {
	int i;
	for (i = 0; i < BLOCKSIZE; ++i)
		printf("%02X ", (unsigned char)blk[i]);
	printf("\n");
}

/* returns the block number given an inode index */
static int block_by_index(int index) {
	return index / BLOCKSIZE;
}

/* returns the structure of the indexed inode */
static inode get_inode(int index) {
	inode ret;
	block blk;  /* read the block containing the inode */
	read_block(block_by_index(index), blk);
	memcpy(&ret, blk + (index % BLOCKSIZE), sizeof(inode));
	if (index < 0)
		ret.index = -1;
	return ret;
}

static int inode_index_by_num(int num) {
	int block_num = (ROOTINODE + num / INODE_PER_BLOCK) * BLOCKSIZE;
	block_num += (num % INODE_PER_BLOCK) * sizeof(inode);
	return block_num;
}

static int inode_index_to_num(int index) {
	int ret = (block_by_index(index) - ROOTINODE) * INODE_PER_BLOCK;
	ret += (index - block_by_index(index) * BLOCKSIZE) / sizeof(inode);
	return ret;
}

static inode make_inode(int index, char type) {
	inode ret;
	memset(&ret, 0, sizeof(inode));
	ret.index = index;
	ret.type = type;
	return ret;
}

static int set_datablock_bitmap(int index, char val) {
	int i = index / 8;
	char v = (1 << (index % 8));
	if (index < 0) return -1;
	data_bitmap[i] = val ? (data_bitmap[i] | v) : (data_bitmap[i] & (~v));
	return i / BLOCKSIZE + BLOCKBITMAP;
}

static void set_inode_bitmap(int index, char val) {
	int i = index / 8;
	char v = (1 << (index % 8));
	inode_bitmap[i] = val ? (inode_bitmap[i] | v) : (inode_bitmap[i] & (~v));
}

static void get_parent_name(char *name, char *buf) {
	int len = strlen(name);
	while (--len)
		if (name[len] == '/')
			break;
	memcpy(buf, name, len > 0 ? len : 2);
	if (len == 0) {
		buf[0] = '/';
		len = 1;
	}
	buf[len] = '\0';
}

static void get_file_name(char *name, char *buf) {
	int len = strlen(name);
	while (--len >= 0)
		if (name[len] == '/') {
			strcpy(buf, name + len + 1);
			break;
		}
}

static char get_datablock_bitmap(int index) {
	char v = data_bitmap[index / 8];
	return (1 << (index % 8)) & v ? 1 : 0;
}

static int get_free_bit_index(char occupy, char *bmp, int start, int size) {
	int i, j;
	char mask;
	for (i = start; i < size; ++i) {
		mask = 1;
		for (j = 0; j < 8; ++j) {
			if (!(mask & bmp[i])) {
				if (occupy) bmp[i] |= mask;
				return i * 8 + j;
			}
			mask <<= 1;
		}
	}
	return -1;
}

static int get_free_data_block(char occupy) {
	int ret = get_free_bit_index(occupy, data_bitmap, DATA_BMP_START_BYTE, BMPSIZE);
	block empty;
	memset(empty, 0, BLOCKSIZE);
	write_block(ret, empty);
	return ret;
}

static int get_free_inode_index(char occupy) {
	return get_free_bit_index(occupy, inode_bitmap, 0, INODE_BMP_SIZE);
}

static void read_offset(int offset, char *buf, int size) {
	int beg_block = offset / BLOCKSIZE;
	int end_block = (offset + size - 1) / BLOCKSIZE;
	int i, addr = offset % BLOCKSIZE;
	int piece = beg_block == end_block ? size : BLOCKSIZE - addr;
	block data;
	for (i = beg_block; i <= end_block; ++i) {
		read_block(i, data);
		memcpy(buf, data + addr, piece);
		buf += piece;
		size -= piece;
		piece = size < BLOCKSIZE ? size : BLOCKSIZE;
		addr = 0;
	}
}

static void load_datablock_bitmap() {
	read_offset(BLOCKBITMAP * BLOCKSIZE, data_bitmap, BMPSIZE);
}

static void load_inode_bitmap() {
	read_block(INODEBITMAP, inode_bitmap);
}

static int find_addr_block(block blk, char *target) {
	int *idx;
	dentry *entry;
	block data_block;
	char *end = blk + BLOCKSIZE;
	char *dend;
	for (idx = (int*)blk; (char*)idx < end; ++idx) {
		if (*idx) {
			read_block(*idx, data_block);
			dend = data_block + BLOCKSIZE;
			for (entry = (dentry*)data_block; (char*)entry < dend; ++entry) {
				if (entry->index && !strcmp(entry->name, target)) 
					return entry->index;
			}
		}
	}
	return -1;
}

static char is_block_empty(int block_num) {
	block blk;
	int i;
	if (block_num < 0) return 1;
	read_block(block_num, blk);
	for (i = 0; i < BLOCKSIZE; ++i)
		if (blk[i]) return 0;
	return 1;
}

static int find_item(int dir_index, char *target) {
	block addr_blk;
	char *secondary_addr;
	int *sidx, ret;
	inode dir = get_inode(dir_index);
	read_block(dir.primary_ptr, addr_blk);
	ret = find_addr_block(addr_blk, target);
	if (ret > 0) return ret;
	if (dir.secondary_ptr != -1) {
		secondary_addr = (char*)malloc(BLOCKSIZE);
		read_block(dir.secondary_ptr, secondary_addr);
		for (sidx = (int*)secondary_addr; *sidx; ++sidx) {
			read_block(*sidx, addr_blk);
			ret = find_addr_block(addr_blk, target);
			if (ret > 0) break;
		}
		free(secondary_addr);
	}
	return ret;
}

/* path must start with root directory, return -1 if not exists. */
static int path_to_inode(char *path) {
	block addr_blk;
	int *idx, index;
	char *dir;
	inode p = get_inode(ROOTINDEX);
	if (path[0] == '\0' || !strcmp("/", path)) return ROOTINDEX;
	if (path[0] != '/') return -1;
	dir = strtok(path + 1, "/");
	for (index = ROOTINDEX; dir; dir = strtok(NULL, "/")) {
		index = find_item(index, dir);
		if (index < 0) return -1;
	}
	return index;
}

/* open an exisiting file for reading or writing */
int my_open(char *path) {
	char dir[512];
	int i, index, ret = free_fd;
	strcpy(dir, path);
	for (i = 0; i < MAX_OPEN_FILES; ++i) {
		if (!open_inode[i] && i != ret) {
			free_fd = i;
			break;
		}
	}
	if (free_fd == ret)
		return -1;
	if (ret == -1) ret = 1;
	index = path_to_inode(dir);
	if (index < 0)
		ret = -1;
	else {
		if (!open_inode[ret])
			open_inode[ret] = (inode*)malloc(sizeof(inode));
		*open_inode[ret] = get_inode(index);
	}
	seek_ptr[ret] = 0;
	return ret;
}

/* node->index overrides index when index is set to -1 */
static void write_inode_to_disk(inode *node, int index) {
	block buf;
	index = index < 0 ? node->index : index;
	read_block(block_by_index(index), buf);
	memcpy(buf + (index % BLOCKSIZE), node, sizeof(inode));
	write_block(block_by_index(index), buf);
}

static int find_space_for_dentry(block addr_block) {
	int *idx, ret;
	dentry *entry;
	char *end = addr_block + BLOCKSIZE;
	block data_block;
	for (idx = (int*)addr_block; (char*)idx < end; ++idx) {
		if (*idx) {
			read_block(*idx, data_block);
			for (entry = (dentry*)data_block; entry->index; ++entry);
			if (BLOCKSIZE - (int)((char*)entry - data_block) >= sizeof(dentry)) {
				ret = *idx;
				memcpy(addr_block, data_block, BLOCKSIZE);
				return ret;
			}
		}
	}
	return -1;
}

static void add_child_to_directory(inode *child, inode *parent) {
	dentry entry, *new_entry;
	char *secondary_addr;
	int addr_index, new_datablock, primary_index;
	int *idx, *sidx, dentry_blk;
	block addr_blk;
	memcpy(entry.name, child->name, sizeof(entry.name));
	entry.index = child->index;
	memset(addr_blk, 0, BLOCKSIZE);
	/* find space for dentry in existing data blocks */
	if (is_block_empty(parent->primary_ptr)) {
		addr_index = get_free_data_block(1);
		*(int*)addr_blk = addr_index;
		write_block(parent->primary_ptr, addr_blk);
	}
	else read_block(parent->primary_ptr, addr_blk);
	dentry_blk = find_space_for_dentry(addr_blk);
	if (dentry_blk > 0) goto found;
	if (dentry_blk < 0 && parent->secondary_ptr != -1) {
		secondary_addr = (char*)malloc(BLOCKSIZE);
		read_block(parent->secondary_ptr, secondary_addr);
		for (sidx = (int*)secondary_addr; *sidx; ++sidx) {
			read_block(*sidx, addr_blk);
			dentry_blk = find_space_for_dentry(addr_blk);
			if (dentry_blk > 0) break;
		}
		free(secondary_addr);
	}
	/* allocate new space for dentries, first check primary block */
	if (dentry_blk < 0) {
		if (parent->secondary_ptr < 0) {
			read_block(parent->primary_ptr, addr_blk);
			if (*(int*)(addr_blk + BLOCKSIZE - 4) != 0) {
				for (idx = (int*)addr_blk; *idx; ++idx);
				dentry_blk = *idx = get_free_data_block(1);
				write_block(parent->primary_ptr, addr_blk);
			}
			if (dentry_blk < 0) {	/* if primary block is full, allocate secondary block */
				memset(addr_blk, 0, BLOCKSIZE);
				parent->secondary_ptr = get_free_data_block(1);
				write_block(parent->secondary_ptr, addr_blk);
			}
		}
		secondary_addr = (char*)malloc(BLOCKSIZE);
		read_block(parent->secondary_ptr, secondary_addr);
		for (sidx = (int*)secondary_addr; *sidx; ++sidx);
		*sidx = get_free_data_block(1);
		write_block(parent->secondary_ptr, secondary_addr);
		read_block(*sidx, addr_blk);
		memset(addr_blk, 0, BLOCKSIZE);
		dentry_blk = *(int*)addr_blk = get_free_data_block(1);
		write_block(*sidx, addr_blk);
		free(secondary_addr);
		read_block(dentry_blk, addr_blk);
	}
found:
	for (new_entry = (dentry*)addr_blk; new_entry->index; ++new_entry);
	memcpy(new_entry, &entry, sizeof(dentry));
	write_block(dentry_blk, addr_blk);
}

/* new_item: 0 to overwrite existing item, 1 to create a new entry */
static char write_dentry_primary_addr(int file_index, block addr, int block_index, dentry *item, char new_item) {
	int *idx, *tmp;
	char *end = addr + BLOCKSIZE, *dend;
	block blk;
	dentry *d;
	int i;
	for (idx = (int*)addr; (char*)idx < end; ++idx) {
		if (*idx) {
			read_block(*idx, blk);
			dend = blk + BLOCKSIZE;
			for (d = (dentry*)blk; (char*)d < dend; ++d) {
				if (!new_item && d->index == file_index) {
					memcpy(d, item, sizeof(dentry));
					write_block(*idx, blk);
					if (is_block_empty(*idx)) {
						set_datablock_bitmap(*idx, 0);
						*idx = 0;
						tmp = idx;
						for (idx = ((int*)end) - 1; !*idx && idx > tmp; --idx);
						*tmp = *idx;
						write_block(block_index, addr);
					}
					return 0;
				}
				else if (new_item) {
					if (!d->index) {
						memcpy(d, item, sizeof(dentry));
						write_block(*idx, blk);
						return 0;
					}
				}
			}
		}
	}
	return -1;
}

static char write_dentry(inode *parent, int file_index, dentry *item, char new_item) {
	block addr_blk;
	char *saddr;
	int *sidx, *tmp, cnt, ub = BLOCKSIZE / sizeof(int);
	dentry *index;
	char ret, *end;
	memset(addr_blk, 0, BLOCKSIZE);
	read_block(parent->primary_ptr, addr_blk);
	ret = write_dentry_primary_addr(file_index, addr_blk, parent->primary_ptr, item, new_item);
	if (ret < 0 && parent->secondary_ptr > 0) {
		saddr = (char*)malloc(BLOCKSIZE);
		read_block(parent->secondary_ptr, saddr);
		end = saddr + BLOCKSIZE;
		for (sidx = (int*)saddr; *sidx; ++sidx) {
			read_block(*sidx, addr_blk);
			ret = write_dentry_primary_addr(file_index, addr_blk, *sidx, item, new_item);
			if (!ret) {
				if (is_block_empty(*sidx)) {
					set_datablock_bitmap(*sidx, 0);
					*sidx = 0;
					tmp = sidx;
					for (sidx = (int*)end - 1; !*sidx && sidx > tmp; --sidx);
					*tmp = *sidx;
					write_block(parent->secondary_ptr, saddr);
				}
				break;
			}
		}
		free(saddr);
	}
	return ret;
}

static char remove_dentry_from_parent(inode *parent, inode *file) {
	dentry d;
	memset(&d, 0, sizeof(dentry));
	return write_dentry(parent, file->index, &d, 0);
}

static int create_file(char *file_path, char type) {
	char *filename;
	int primary_addr_block, data_block;
	int len;
	int n_inode;
	block addr_blk;
	inode node, dir;
	len = strlen(file_path);
	while (file_path[--len] != '/');
	file_path[len] = '\0';
	dir = get_inode(path_to_inode(file_path));
	file_path[len] = '/';
	filename = file_path + len + 1;
	/* tag bitmaps */
	primary_addr_block = get_free_data_block(1);		/* tag primary address block */
	n_inode = get_free_inode_index(1);					/* tag inode bitmap */
	if (n_inode > 0  && primary_addr_block > 0) {
		node = make_inode(inode_index_by_num(n_inode), type);
		memset(addr_blk, 0, BLOCKSIZE);
		node.primary_ptr = primary_addr_block;
		node.secondary_ptr = -1;
		strcpy(node.name, filename);
		write_block(primary_addr_block, addr_blk);
		write_inode_to_disk(&node, -1);
		add_child_to_directory(&node, &dir);
		return node.index;
	}
	return -1;
}

/* open a new file for writing only */
int my_creat(char *path) {
	char dir[512];
	strcpy(dir, path);
	int index = create_file(dir, FS_FILE);
	if (index > 0) {
		int ret = my_open(path);
		return ret;
	}
	return -1;
}

static void release_space(char *addr_blk) {
	int *idx, *end = (int*)(addr_blk + BLOCKSIZE);
	block buf;
	memset(buf, 0, BLOCKSIZE);
	for (idx = (int*)addr_blk; idx < end; ++idx) {
		if (*idx) {
			set_datablock_bitmap(*idx, 0);
			write_block(*idx, buf);
		}
	}
}

static void release_file_space(int primary_ptr, int secondary_ptr) {
	int *sidx, *end;
	char *saddr_blk;
	block addr_blk;
	read_block(primary_ptr, addr_blk);
	release_space(addr_blk);
	if (secondary_ptr > 0) {
		saddr_blk = (char*)malloc(BLOCKSIZE);
		end = (int*)(saddr_blk + BLOCKSIZE);
		read_block(secondary_ptr, saddr_blk);
		for (sidx = (int*)saddr_blk; sidx < end; ++sidx) {
			if (*sidx) {
				read_block(*sidx, addr_blk);
				release_space(addr_blk);
				set_datablock_bitmap(*sidx, 0);
			}
		}
		free(saddr_blk);
	}
}

static void allocate_file_space(inode *node, int space) {
	int n_blocks = (int)ceil((float)space / (float)BLOCKSIZE);
	int n_primary_address = n_blocks >= PTRPERBLOCK ? PTRPERBLOCK : n_blocks;
	int n_secondary_address = n_blocks - PTRPERBLOCK;
	int n_secondary_block = (int)ceil((float)n_secondary_address / (float)PTRPERBLOCK);
	int i, j, c, u;
	int primary_block[PTRPERBLOCK];
	int *secondary_block;
	read_block(node->primary_ptr, (char*)primary_block);
	for (i = 0; i < n_primary_address; ++i)
		if (!primary_block[i])
			primary_block[i] = get_free_data_block(1);
	write_block(node->primary_ptr, (char*)primary_block);
	if (n_secondary_address > 0) {
		secondary_block = (int*)malloc(BLOCKSIZE);
		if (node->secondary_ptr < 0) {
			node->secondary_ptr = get_free_data_block(1);
			memset(secondary_block, 0, BLOCKSIZE);
			write_block(node->secondary_ptr, (char*)secondary_block);
		}
		read_block(node->secondary_ptr, (char*)secondary_block);
		for (i = 0; i < n_secondary_block; ++i) {
			if (!secondary_block[i]) {
				secondary_block[i] = get_free_data_block(1);
				n_blocks -= PTRPERBLOCK;
				u = n_blocks > PTRPERBLOCK ? PTRPERBLOCK : n_blocks;
				memset(primary_block, 0, BLOCKSIZE);
				for (j = 0; j < u; ++j)
					primary_block[j] = get_free_data_block(1);
				write_block(secondary_block[i], (char*)primary_block);
			}
		}
		write_block(node->secondary_ptr, (char*)secondary_block);
		free(secondary_block);
	}
	else node->secondary_ptr = -1;
	node->size = space;
	write_inode_to_disk(node, -1);
}

static void* block_transfer(int fd, int offset, int nblock, 
							void *start, void *ptr, int count, char mode) {
	int remain = count - (int)(ptr - start);
	int nbytes = remain > BLOCKSIZE - offset ? BLOCKSIZE - offset : remain;
	block buf;
	if (mode == 'w') {
		read_block(nblock, buf);
		memcpy(buf + offset, ptr, nbytes);
		write_block(nblock, buf);
	}
	else {
		read_block(nblock, buf);
		memcpy(ptr, buf + offset, nbytes);
	}
	seek_ptr[fd] += nbytes;
	ptr += nbytes;
	ptr = (int)(ptr - start) < count ? ptr : 0;
	return ptr;
}

/* entity that executes read or write */
static int read_write_worker(int fd, void *buf, int count, char mode) {
	inode *node = open_inode[fd];
	int n_blocks = count / BLOCKSIZE;
	void *ptr = buf;
	block blk;
	char *saddr, *end, *send;
	int *idx, *sidx, ret = count;
	int block_offset, byte_offset, sblock_offset;
	if (!node) return -1;
	/* allocate space */
	if (mode == 'w')
		allocate_file_space(node, count + seek_ptr[fd]);
	/* get offset */
	block_offset = seek_ptr[fd] / BLOCKSIZE;
	byte_offset = seek_ptr[fd] % BLOCKSIZE;
	/* transfer primary block */
	if (block_offset < PTRPERBLOCK) {
		read_block(node->primary_ptr, blk);
		end = blk + BLOCKSIZE;
		for (idx = (int*)blk + block_offset; idx < (int*)end; ++idx)
			if (*idx) {
				ptr = block_transfer(fd, byte_offset, *idx, buf, ptr, count, mode);
				byte_offset = 0;
				if (!ptr) break;
			}
			else ret = -1;
	}
	/* transfer secondary block */
	if (node->secondary_ptr > 0) {
		saddr = (char*)malloc(BLOCKSIZE);
		read_block(node->secondary_ptr, saddr);
		send = saddr + BLOCKSIZE;
		sblock_offset = (block_offset - PTRPERBLOCK) / PTRPERBLOCK;
		sblock_offset = sblock_offset < 0 ? 0 : sblock_offset;
		/* evaluate the start offset in secondary block */
		for (sidx = (int*)saddr + sblock_offset; sidx < (int*)send; ++sidx) {
			if (*sidx) {
				read_block(*sidx, blk);
				end = blk + BLOCKSIZE;
				block_offset = block_offset % PTRPERBLOCK;
				for (idx = (int*)blk + block_offset; idx < (int*)end; ++idx) {
					if (*idx) {
						ptr = block_transfer(fd, byte_offset, *idx, buf, ptr, count, mode);
						byte_offset = 0;
						block_offset = 0;
						if (!ptr) break;
					}
					else ret = -1;
					sblock_offset = 0;
				}
				if (!ptr) break;
			}
		}
		free(saddr);
	}
	return ret;
}

/* sequentially read from a file */
int my_read(int fd, void *buf, int count) {
	return read_write_worker(fd, buf, count, 'r');
}

/* sequentially write to a file */
int my_write(int fd, void *buf, int count) {
	return read_write_worker(fd, buf, count, 'w');
}

int my_close(int fd) {
	seek_ptr[fd] = 0;
	if (open_inode[fd]) {
		free(open_inode[fd]);
		open_inode[fd] = NULL;
	}
	free_fd = fd;
	return 0;
}

static void remove_inode(int index) {
	inode empty_inode;
	set_inode_bitmap(inode_index_to_num(index), 0);
	memset(&empty_inode, 0, sizeof(inode));
	write_inode_to_disk(&empty_inode, index);
}

int my_remove(char *path) {
	char ret, parent_dir[256], file_dir[256], *saddr_blk;
	inode parent, file;
	get_parent_name(path, parent_dir);
	strcpy(file_dir, path);
	parent = get_inode(path_to_inode(parent_dir));
	file = get_inode(path_to_inode(file_dir));
	/* fail on non-existing files */
	if (parent.index < 0 || file.index < 0)
		return -1;
	/* release inode space */
	remove_inode(file.index);
	/* release space in primary and secondary indices */
	release_file_space(file.primary_ptr, file.secondary_ptr);
	/* remove path from parent and release space */
	set_datablock_bitmap(file.primary_ptr, 0);
	set_datablock_bitmap(file.secondary_ptr, 0);
	return remove_dentry_from_parent(&parent, &file);
}

int my_rename(char *old, char *new) {
	inode parent, file, new_parent;
	dentry entry;
	char ret;
	char old_parent[256], new_parent_name[256], new_name[64], old_safe[256];
	strcpy(old_safe, old);
	get_file_name(new, new_name);
	get_parent_name(old, old_parent);
	get_parent_name(new, new_parent_name);
	parent = get_inode(path_to_inode(old_parent));
	file = get_inode(path_to_inode(old_safe));
	new_parent = get_inode(path_to_inode(new_parent_name));
	/* update inode */
	strcpy(file.name, new_name);
	write_inode_to_disk(&file, -1);
	/* update dentry */
	entry.index = file.index;
	strcpy(entry.name, new_name);
	ret = remove_dentry_from_parent(&parent, &file);
	ret |= write_dentry(&new_parent, file.index, &entry, 1);
	return ret;
}

/* only works if all but the last component of the path already exists */
int my_mkdir(char * path) {
	char dir[512];
	strcpy(dir, path);
	int index = create_file(dir, FS_DIRECTORY);
	if (index > 0)
		return 0;
	return -1;
}

int my_rmdir(char *path) {
	char ret, parent_dir[256], file_dir[256];
	inode parent, file, empty_inode;
	get_parent_name(path, parent_dir);
	strcpy(file_dir, path);
	parent = get_inode(path_to_inode(parent_dir));
	file = get_inode(path_to_inode(file_dir));
	/* fail on non-empty directories */
	if (!is_block_empty(file.primary_ptr) || !is_block_empty(file.secondary_ptr))
		return -1;
	/* release inode space */
	set_inode_bitmap(inode_index_to_num(file.index), 0);
	memset(&empty_inode, 0, sizeof(inode));
	write_inode_to_disk(&empty_inode, file.index);
	/* remove path from parent and release space */
	set_datablock_bitmap(file.primary_ptr, 0);
	set_datablock_bitmap(file.secondary_ptr, 0);
	return remove_dentry_from_parent(&parent, &file);
}

/* check the signature of the filesystem */
char check_fs(block superblock) {
	return 0; /* for debug */
	if (((SIGNATURE & 0xFF) == superblock[0]) 
		&& (((SIGNATURE >> 8) & 0xFF) == superblock[1]))
		return 1;
	else return 0;
}

/* check to see if the device already has a file system on it,
 * and if not, create one. */
void my_mkfs() {
	int dev_size = dev_open();
	int ret, i, p = DATABLOCK + 1;
	block superblock;
	ret = read_block(0, superblock);
	if (ret == -1 || !check_fs(superblock)) {
		memset(open_inode, 0, sizeof(open_inode));
		superblock[0] = SIGNATURE & 0xFF;
		superblock[1] = (SIGNATURE >> 8) & 0xFF;
		write_block(0, superblock);
		memset(superblock, 0, BLOCKSIZE);
		memset(data_bitmap, 0, sizeof(data_bitmap));
		/* init inode space */
		for (i = 1; i < RESERVEDBLOCKS; ++i) {
			/* break; /* for debug */
			write_block(i, superblock);
		}
		/* create inode for root */
		inode root = make_inode(ROOTINDEX, 1);
		root.primary_ptr = DATABLOCK;
		root.secondary_ptr = -1;
		strcpy(root.name, "/");
		/* write inode bitmap */
		memset(inode_bitmap, 0, sizeof(block));
		inode_bitmap[0] = 1;
		write_block(INODEBITMAP, inode_bitmap);
		/* write root inode */
		memset(superblock, 0, sizeof(block));
		memcpy(superblock, &root, sizeof(inode));
		write_block(ROOTINODE, superblock);
		/* assign the first datablock as primary address block */
		i = set_datablock_bitmap(DATABLOCK, 1);
		write_block(i, data_bitmap + (i - BLOCKBITMAP) * BLOCKSIZE);
		/* assign the second datablock as the data block */
		i = set_datablock_bitmap(p, 1);
		write_block(i, data_bitmap + (i - BLOCKBITMAP) * BLOCKSIZE);
		/* write the primary address block to store block address */
		memset(superblock, 0, sizeof(block));
		memcpy(superblock, &p, sizeof(int));
		write_block(DATABLOCK, superblock);
		/* clear the data block pointed by the address */
		memset(superblock, 0, sizeof(block));
		write_block(p, superblock);
	}
}

void my_closefs() {
	int i;
	for (i = 1; i <= 32; ++i)
		write_block(i, data_bitmap + (i - 1) * BLOCKSIZE);
	write_block(511, inode_bitmap);
}