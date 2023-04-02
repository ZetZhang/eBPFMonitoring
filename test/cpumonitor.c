#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u64 ip;
};

BPF_HASH(start, u32);
BPF_HASH(cpu_time, struct key_t);

int do_perf_event(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();

    start.update(&pid, &ts);

    return 0;
}

int do_sched_process_fork(struct pt_regs *ctx, struct task_struct *parent, struct task_struct *child) {
    u32 pid = child->pid;
    u64 ts = bpf_ktime_get_ns();

    start.update(&pid, &ts);

    return 0;
}

int do_sched_process_exit(struct pt_regs *ctx, struct task_struct *task) {
    u32 pid = task->pid;
    u64 *tsp = start.lookup(&pid);

    if (tsp != 0) {
        u64 now = bpf_ktime_get_ns();
        u64 delta = now - *tsp;

        // Update CPU time for process
        struct key_t key = {};
        key.ip = pid;
        u64 *val = cpu_time.lookup_or_init(&key, &delta);
        (*val) += delta;

        // Delete start time for process
        start.delete(&pid);
    }

    return 0;
}

int do_timer(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u64 sum = 0;

    // Calculate total CPU time for all processes
    struct key_t key = {};
    u64 *val;
    bpf_map_for_each(&cpu_time, &key, &val) {
        sum += (*val);
    }

    // Calculate CPU utilization
    u64 elapsed = ts / 1000000;
    u64 usage = sum / elapsed;
    bpf_trace_printk("%llu\n", usage);

    // Reset CPU time for all processes
    cpu_time.delete(&key);

    return 0;
}

