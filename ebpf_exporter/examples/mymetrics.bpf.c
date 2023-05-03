#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_CPUS 512

// Max number of disks we expect to see on the host
#define MAX_DISKS 255

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 27

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

extern int LINUX_KERNEL_VERSION __kconfig;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct request *);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * MAX_DISKS);
    __type(key, struct disk_latency_key_t);
    __type(value, u64);
} bio_latency SEC(".maps");

struct disk_latency_key_t {
    u32 dev;
    u8 op;
    u64 slot;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} ref_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} miss_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, u64);
    __type(value, u64);
} page_cache_ops_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} oom_kills_total SEC(".maps");

static int trace_event(void *map, u32 cpu, u64 sample_period)
{
    increment_map(map, &cpu, sample_period);

    return 0;
}

SEC("perf_event/type=0,config=3,frequency=1")
int on_cache_miss(struct bpf_perf_event_data *ctx)
{
    return trace_event(&miss_total, bpf_get_smp_processor_id(), ctx->sample_period);
}

SEC("perf_event/type=0,config=2,frequency=1")
int on_cache_ref(struct bpf_perf_event_data *ctx)
{
    return trace_event(&ref_total, bpf_get_smp_processor_id(), ctx->sample_period);
}

struct request_queue___x {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x {
    struct request_queue___x *q;
    struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request)
{
    struct request___x *r = request;

    if (bpf_core_field_exists(r->rq_disk))
        return BPF_CORE_READ(r, rq_disk);
    return BPF_CORE_READ(r, q, disk);
}

static __always_inline int trace_rq_start(struct request *rq)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &rq, &ts, 0);
    return 0;
}

SEC("raw_tp/block_rq_insert")
int block_rq_insert(struct bpf_raw_tracepoint_args *ctx)
{
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
        return trace_rq_start((void *) ctx->args[1]);
    } else {
        return trace_rq_start((void *) ctx->args[0]);
    }
}

SEC("raw_tp/block_rq_issue")
int block_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
        return trace_rq_start((void *) ctx->args[1]);
    } else {
        return trace_rq_start((void *) ctx->args[0]);
    }
}

SEC("raw_tp/block_rq_complete")
int block_rq_complete(struct bpf_raw_tracepoint_args *ctx)
{
    u64 *tsp, flags, delta_us, latency_slot;
    struct gendisk *disk;
    struct request *rq = (struct request *) ctx->args[0];
    struct disk_latency_key_t latency_key = {};

    tsp = bpf_map_lookup_elem(&start, &rq);
    if (!tsp) {
        return 0;
    }

    // Delta in microseconds
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // Latency histogram key
    latency_slot = log2l(delta_us);

    // Cap latency bucket at max value
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }

    disk = get_disk(rq);
    flags = BPF_CORE_READ(rq, cmd_flags);

    latency_key.slot = latency_slot;
    latency_key.dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
    latency_key.op = flags & REQ_OP_MASK;

    increment_map(&bio_latency, &latency_key, 1);

    latency_key.slot = MAX_LATENCY_SLOT + 1;
    increment_map(&bio_latency, &latency_key, delta_us);

    bpf_map_delete_elem(&start, &rq);

    return 0;
}

struct data_t {
    // u64 cgroup_id;
    u8 global_oom;
};

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(kprobe__oom_kill_process, struct oom_control *oc, const char *message)
{
    struct data_t data = {};

    struct mem_cgroup *mcg = BPF_CORE_READ(oc, memcg);
    if (!mcg) {
        data.global_oom = 1;
        bpf_perf_event_output(ctx, &oom_kills_total, BPF_F_CURRENT_CPU, &data, sizeof(data));
        return 0;
    }

    // data.cgroup_id = BPF_CORE_READ(mcg, css.cgroup, kn, id);
    bpf_perf_event_output(ctx, &oom_kills_total, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
