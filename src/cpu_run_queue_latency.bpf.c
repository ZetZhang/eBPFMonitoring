#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "cpu_run_queue_latency.h"

#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

// wakeup & new 记录起始时间戳
static int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;
	// 如果进程ID为0则退出
	if (!pid)
		return 0;
	// 如果进程组ID不为0,但不与当前进程组相同则退出
	if (targ_tgid && targ_tgid != tgid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

// PID是系统全局唯一标识，但不同PID namespace下相同的PID可以对应不同进程，因此需要避免PID冲突
static unsigned int pid_namespace(struct task_struct *task)
{
	struct pid *pid;
	unsigned int level, inum;
	struct upid upid;

	pid = BPF_CORE_READ(task, thread_pid);	// task->thread_pid类型指针
	level = BPF_CORE_READ(pid, level);		// pid层级
	bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]); // pid->numbers下level对应的upid结构体
	inum = BPF_CORE_READ(upid.ns, ns.inum);	// upid.ns的ns.inum表示PID所在namespace的inode号

	return inum;
}

// switch 跟踪进程调度并记录运行时间
static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
    struct hist *histp;
    u64 *tsp, slot;
	u32 pid, hkey;
	s64 delta;
	// start Map记录前一个进程状态，表示进程开始运行
    if (get_task_state(prev) == TASK_RUNNING)
		trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));
	// 查找当前pid的开始运行时间，不存在则退出
    pid = BPF_CORE_READ(next, pid);
    if (!(tsp = bpf_map_lookup_elem(&start, &pid)))
        return 0;
	// 计算时差
    if ((delta = bpf_ktime_get_ns() - *tsp) < 0)
        goto cleanup;
	// 直方图Map作key
    if (targ_per_process)
		hkey = BPF_CORE_READ(next, tgid);
	else if (targ_per_thread)
		hkey = pid;
	else if (targ_per_pidns)
		hkey = pid_namespace(next);
	else
		hkey = -1;
	// hists中包含slots和comm
	if (!(histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero)))
		goto cleanup;
	if (!histp->comm[0])
		bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm), next->comm);
	// 计算直方图slots位，并增加其计数值
	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	// 删除pid的运行时间记录，等待下次进程调度
    bpf_map_delete_elem(&start, &pid);
    return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";