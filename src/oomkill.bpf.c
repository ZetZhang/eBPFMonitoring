#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct data_t {
    u64 cgroup_id;
    u8 global_oom;
};

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(kprobe__oom_kill_process, struct oom_control *oc, const char *message)
{
    struct data_t *data = NULL;

    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (!data)
		return 0;

    struct mem_cgroup *mcg = BPF_CORE_READ(oc, memcg);
    if (!mcg) {
        data->global_oom = 1;
        bpf_ringbuf_submit(data, 0);
        return 0;
    }

    data->cgroup_id = BPF_CORE_READ(mcg, css.cgroup, kn, id);

    bpf_ringbuf_submit(data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";