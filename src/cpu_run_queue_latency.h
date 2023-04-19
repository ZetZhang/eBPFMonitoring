#ifndef __CPU_RUN_QUEUE_LATENCY_H__
#define __CPU_RUN_QUEUE_LATENCY_H__

#define TASK_COMM_LEN	16
#define MAX_SLOTS	    26
#define MAX_ENTRIES	    10240
#define TASK_RUNNING 	0

struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
};

#endif // __CPU_RUN_QUEUE_LATENCY_H__