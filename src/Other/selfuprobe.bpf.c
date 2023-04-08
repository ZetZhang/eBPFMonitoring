#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

unsigned long long func_entry_time = 0;
unsigned long long func_exit_time = 0;

SEC("uprobe/func-exec-time")
int BPF_KPROBE(uprobe)
{
    func_entry_time = bpf_ktime_get_ns();
    return 0;
}

SEC("uretprobe/func-exec-time")
int BPF_KRETPROBE(uretprobe)
{
    func_exit_time = bpf_ktime_get_ns();

    bpf_printk("function execute time:%lu\n", func_exit_time - func_entry_time);

    return 0;
}
