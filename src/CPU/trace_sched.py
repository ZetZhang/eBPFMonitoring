#!/usr/bin/env python

from bcc import BPF
from ctypes import c_ulonglong
import time

bpf_text = """
#include <uapi/linux/ptrace.h>

struct queue_info {
    u64 queue_length;
    u64 queue_delay;
};

BPF_HASH(queue_stats, u32, struct queue_info);

int trace_sched_stat_runtime(struct pt_regs *ctx, pid_t pid, __u64 delta) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct queue_info *info = queue_stats.lookup(&tgid);
    if (info) {
        info->queue_length += 1;
        info->queue_delay += delta;
    } else {
        struct queue_info new_info = { 0 };
        queue_stats.insert(&tgid, &new_info);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="sched_stat_runtime", fn_name="trace_sched_stat_runtime")

print("Tracking CPU run queue length and delay... Hit Ctrl-C to end.")

try:
    while True:
        queue_stats = b.get_table("queue_stats")
        for key, value in queue_stats.items():
            tgid = key.value
            info = value.value
            if info:
                queue_length = info.queue_length
                queue_delay = info.queue_delay
                print("TGID: %d, Queue length: %d, Queue delay: %d" % (tgid, queue_length, queue_delay))
        time.sleep(1)
except KeyboardInterrupt:
    pass

