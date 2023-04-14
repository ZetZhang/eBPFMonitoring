// off cpu time
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

#define STACK_STORAGE_SIZE 1024
struct key_t {
    u32 pid;
    u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};

struct warn_event_t {
    u32 pid;
    u32 tgid;
    u32 t_start;
    u32 t_end;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct key_t);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, STACK_STORAGE_SIZE);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} warn_events SEC(".maps");

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts, *tsp;
    // record previous thread sleep time
    if ((THREAD_FILTER) && (STATE_FILTER)) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }
    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    // tsp = start.lookup(&pid);
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }
    // calculate current thread's delta time
    u64 t_start = *tsp;
    u64 t_end = bpf_ktime_get_ns();
    // start.delete(&pid);
    bpf_map_delete_elem(&start, &pid);
    if (t_start > t_end) {
        struct warn_event_t event = {
            .pid = pid,
            .tgid = tgid,
            .t_start = t_start,
            .t_end = t_end,
        };
        warn_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    u64 delta = t_end - t_start;
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }
    // create map key
    struct key_t key = {};
    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;
    bpf_get_current_comm(&key.name, sizeof(key.name));
    // counts.increment(key, delta);
    __sync_fetch_and_add(count, delta);
    return 0;
}