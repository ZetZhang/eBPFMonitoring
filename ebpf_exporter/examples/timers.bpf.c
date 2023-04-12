#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} timer_starts_total SEC(".maps");

SEC("tracepoint/timer/timer_start")
int do_count(struct trace_event_raw_timer_start* ctx)
{
    u64 function = (u64) ctx->function;

    increment_map(&timer_starts_total, &function, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
