#ifndef __VFS_CACHE_READAHEAD_H__
#define __VFS_CACHE_READAHEAD_H__

#define MAX_SLOTS	20

struct hist {
	__u32 unused;
	__u32 total;
	__u32 slots[MAX_SLOTS];
};

#endif // __VFS_CACHE_READAHEAD_H__