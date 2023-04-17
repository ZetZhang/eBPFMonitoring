// cpu run queue length or claimed
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "claimed.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

// struct cfs_rq_partial {
//     struct load_weight load;
//     // unsigned long runnable_weight;
//     unsigned int nr_running, h_nr_running;
// };

#ifdef IS_KPROBE_RQ_CLOCK
// update_rq_clock()被scheduler_tick()函数调用
// 周期性调度器在系统活动时自动调用，是队列的时钟更新
SEC("kprobe/update_rq_clock")
#else
SEC("perf_event")
#endif
int claimed_event(struct trace_event_raw_sched_process_exec *ctx)
{
    uint64_t cpu = bpf_get_smp_processor_id();
    uint64_t now = bpf_ktime_get_ns();

    unsigned int len = 0;
    struct task_struct *task = NULL;
    // struct cfs_rq_partial *cfs_rq = NULL;
    struct data_t *data = NULL;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    // `task->se`是一个指向 `struct sched_entity` 的指针，
    // 它包含了与进程调度相关的信息，包括进程的调度策略、优先级、运行时间等等。
    len = BPF_CORE_READ(task, se.cfs_rq, nr_running);

    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
	if (!data)
		return 0;
    data->ts = now;
    data->cpu = cpu;
    data->len = len;

    bpf_ringbuf_submit(data, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
