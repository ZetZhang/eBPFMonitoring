#ifndef __CPU_HIT_SITUATION_H__
#define __CPU_HIT_SITUATION_H__

#define TASK_COMM_LEN 16

#define MAX_ENTRIES 10240

struct value_info {
	__u64 ref;
	__u64 miss;
	char comm[TASK_COMM_LEN];
};

struct key_info {
	__u32 cpu;
	__u32 pid;
	__u32 tid;
};

#endif // __CPU_HIT_SITUATION_H__