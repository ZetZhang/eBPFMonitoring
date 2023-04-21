#ifndef __VFS_IOSTAT_H__
#define __VFS_IOSTAT_H__

enum stat_types {
	S_READ,
	S_WRITE,
	S_FSYNC,
	S_OPEN,
	S_CREATE,
	S_MAXSTAT,
};

#endif // __VFS_IOSTAT_H__