#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "compat.bpf.h"
#include "mem_oomkill.h"

// struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(key_size, sizeof(u32));
//     __uint(value_size, sizeof(u32));
// } oom_kills_total SEC(".maps");

// 统计发生OOM kill的进程信息
SEC("kprobe/oom_kill_process")
int BPF_KPROBE(kprobe__oom_kill_process, struct oom_control *oc, const char *message)
{
    struct data_t *data = NULL;

    if (!(data = reserve_buf(sizeof(*data))))
        return 0;
    // 记录发生oomkill和被oomkill的进程pid和进程名
    data->fpid = bpf_get_current_pid_tgid() >> 32;
	data->tpid = BPF_CORE_READ(oc, chosen, tgid);
	data->pages = BPF_CORE_READ(oc, totalpages);
    bpf_get_current_comm(&data->fcomm, sizeof(data->fcomm));
    bpf_probe_read_kernel(&data->tcomm, sizeof(data->tcomm), BPF_CORE_READ(oc, chosen, comm));
	submit_buf(ctx, data, sizeof(*data)); // ringbuf
    // bpf_perf_event_output(ctx, &oom_kills_total, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";