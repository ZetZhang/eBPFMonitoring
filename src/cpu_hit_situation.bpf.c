#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cpu_hit_situation.h"

const volatile bool targ_per_thread = false;

struct key_t {
    int cpu;
    u32 pid;
    u32 tid;
    char name[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, key_t);
} ref_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, key_t);
} miss_count SEC(".maps");

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    key->cpu = bpf_get_smp_processor_id();
    key->pid = pid_tgid >> 32;
    key->tid = key->pid;
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

SEC("perf_event")
int on_cache_miss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    // miss_count.increment(key, ctx->sample_period);
    return 0;
}

SEC("perf_event")
int on_cache_ref(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    // ref_count.increment(key, ctx->sample_period);
    return 0;
}