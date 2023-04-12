#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "claimed.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} pb SEC(".maps");

// FIXME: segment fault
SEC("tp/sched/sched_process_exec")
int claimed_event(struct trace_event_raw_sched_process_exec *ctx)
{
    uint64_t cpu = bpf_get_smp_processor_id();
    uint64_t now = bpf_ktime_get_ns();

    int zero = 0;
    unsigned int len = 0;
    struct task_struct *task = NULL;
    // struct cfs_rq_partial *cfs_rq = NULL;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    len = BPF_CORE_READ(task, se.cfs_rq, nr_running);

    struct data_t data = {.ts = now, .cpu = cpu, .len = len};

    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &data, sizeof(struct data_t));
    return 0;
}

char _license[] SEC("license") = "GPL";
