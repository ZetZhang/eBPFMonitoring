#ifndef __MEM_OOMKILL_H__
#define __MEM_OOMKILL_H__

#define TASK_COMM_LEN 16

struct data_t {
	__u32 fpid;
	__u32 tpid;
	__u64 pages;
	char fcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
};

#endif // __MEM_OOMKILL_H__