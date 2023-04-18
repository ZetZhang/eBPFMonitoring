#ifndef __CPU_RUN_QUEUE_LENGTH_H__
#define __CPU_RUN_QUEUE_LENGTH_H__

#define MAX_CPU_NR	128
#define MAX_SLOTS	32

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif // __CPU_RUN_QUEUE_LENGTH_H__
