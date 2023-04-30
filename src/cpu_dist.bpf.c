#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "cpu_dist.h"
#include "bits.bpf.h"
#include "core_fixes.bpf.h"

#define TASK_RUNNING	0

const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_offcpu = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

static struct hist initial_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

// 记录指定进程的开始执行时间
static __always_inline void store_start(u32 tgid, u32 pid, u64 ts)
{
	// 如果targ_tgid参数不等于-1且不等于当前进程的tgid（线程组ID），则直接返回，不进行记录
	if (targ_tgid != -1 && targ_tgid != tgid)
		return;
	// 否则将当前进程的pid作为key，将时间戳ts插入到start Map中
	bpf_map_update_elem(&start, &pid, &ts, 0);
}

// 更新指定进程或线程的执行时间分布直方图
static __always_inline void update_hist(struct task_struct *task, u32 tgid, u32 pid, u64 ts)
{
	u64 delta, *tsp, slot;
	struct hist *histp;
	u32 id;

	// 如果不是-1或特定进程组则退出
	if (targ_tgid != -1 && targ_tgid != tgid)
		return;
	// 如果不为空，检查指定进程启动的时间是否正常
	if (!(tsp = bpf_map_lookup_elem(&start, &pid)) || ts < *tsp)
		return;
	// 通过用户态程序的设置，来判断是process、thread还是全部进程来作为直方图索引
	if (targ_per_process)
		id = tgid;
	else if (targ_per_thread)
		id = pid;
	else
		id = -1;
	// 如果对应的直方图不存在则初始化，并获取进程名
	if (!(histp = bpf_map_lookup_elem(&hists, &id))) {
		bpf_map_update_elem(&hists, &id, &initial_hist, 0);
		if (!(histp = bpf_map_lookup_elem(&hists, &id)))
			return;
		BPF_CORE_READ_STR_INTO(&histp->comm, task, comm);
	}
	// 计算时差的分布情况并增加对应计数
	delta = ts - *tsp;
	if (targ_ms)
		delta /= 1000000;
	else
		delta /= 1000;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
}

// 处理进程间的切换事件
static int handle_switch(struct task_struct *prev, struct task_struct *next)
{
	u32 prev_tgid = BPF_CORE_READ(prev, tgid), prev_pid = BPF_CORE_READ(prev, pid);
	u32 tgid = BPF_CORE_READ(next, tgid), pid = BPF_CORE_READ(next, pid);
	u64 ts = bpf_ktime_get_ns();

	if (targ_offcpu) {  // 统计系统资源等待，统计off-cpu时间
		store_start(prev_tgid, prev_pid, ts);
		update_hist(next, tgid, pid, ts);
	} else { 			// 统计on-cpu时间
		if (get_task_state(prev) == TASK_RUNNING)
			update_hist(prev, prev_tgid, prev_pid, ts);
		store_start(tgid, pid, ts);
	}
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_btf, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(prev, next);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_tp, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(prev, next);
}

char LICENSE[] SEC("license") = "GPL";