#ifndef __RUNQLEN_H__
#define __RUNQLEN_H__

#define MAX_CPU_NR	128
#define MAX_SLOTS	32

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif // __RUNQLEN_H__
