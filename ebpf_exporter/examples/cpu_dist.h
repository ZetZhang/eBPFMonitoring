#ifndef __CPU_DIST_H__
#define __CPU_DIST_H__

#define TASK_COMM_LEN	16
#define MAX_SLOTS	36

struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
};

#endif // __CPU_DIST_H__