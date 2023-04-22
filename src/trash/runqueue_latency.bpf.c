#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

typedef struct pid_key {
    u32 id;
    u64 slot;
} pid_key_t;

typedef struct pidns_key {
    u32 id;
    u64 slot;
} pidns_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, u32);
    __type(value, u32);
} start SEC(".maps");

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (pid == 0) // tgid != pid 
        return 0;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, 0);
    return 0;
}

static __always_inline unsigned int pid_namespace(struct task_struct *task)
{
/* pids[] was removed from task_struct since commit 2c4704756cab7cfa031ada4dab361562f0e357c0
 * Using the macro INIT_PID_LINK as a conditional judgment.
 */
#ifdef INIT_PID_LINK
    struct pid_link pids;
    unsigned int level;
    struct upid upid;
    struct ns_common ns;
    /*  get the pid namespace by following task_active_pid_ns(),
     *  pid->numbers[pid->level].ns
     */
    bpf_probe_read_kernel(&pids, sizeof(pids), &task->pids[PIDTYPE_PID]);
    bpf_probe_read_kernel(&level, sizeof(level), &pids.pid->level);
    bpf_probe_read_kernel(&upid, sizeof(upid), &pids.pid->numbers[level]);
    bpf_probe_read_kernel(&ns, sizeof(ns), &upid.ns->ns);
    return ns.inum;
#else
    struct pid *pid;
    unsigned int level;
    struct upid upid;
    struct ns_common ns;
    /*  get the pid namespace by following task_active_pid_ns(),
     *  pid->numbers[pid->level].ns
     */
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->thread_pid);
    bpf_probe_read_kernel(&level, sizeof(level), &pid->level);
    bpf_probe_read_kernel(&upid, sizeof(upid), &pid->numbers[level]);
    bpf_probe_read_kernel(&ns, sizeof(ns), &upid.ns->ns);
    return ns.inum;
#endif
}

int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}
int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->tgid, p->pid);
}
// calculate latency
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid, tgid;
    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->__state == TASK_RUNNING) { 
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            bpf_map_update_elem(&start, &pid, &ts, 0);
        }
    }
    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();
    if (pid == 0)
        return 0;
    u64 *tsp, delta;
    // fetch timestamp and calculate delta
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000000;
    // store as histogram
    // STORE
    bpf_map_delete_elem(&start, pid);
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}
RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}
RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;
    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->__state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }
    tgid = next->tgid;
    pid = next->pid;
    if (pid == 0)
        return 0;
    u64 *tsp, delta;
    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000000;
    // store as histogram
    // STORE
    bpf_map_delete_elem(&start, pid);
    return 0;
}