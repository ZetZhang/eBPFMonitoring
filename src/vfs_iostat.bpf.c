#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vfs_iostat.h"

__u64 stats[S_MAXSTAT] = {};

// SEC("kprobe/vfs_read")
// int BPF_KPROBE(kprobe_vfs_read)
// {
// 	return inc_stats(S_READ);
// }

// SEC("kprobe/vfs_write")
// int BPF_KPROBE(kprobe_vfs_write)
// {
// 	return inc_stats(S_WRITE);
// }

// SEC("kprobe/vfs_fsync")
// int BPF_KPROBE(kprobe_vfs_fsync)
// {
// 	return inc_stats(S_FSYNC);
// }

// SEC("kprobe/vfs_open")
// int BPF_KPROBE(kprobe_vfs_open)
// {
// 	return inc_stats(S_OPEN);
// }

// SEC("kprobe/vfs_create")
// int BPF_KPROBE(kprobe_vfs_create)
// {
// 	return inc_stats(S_CREATE);
// }

SEC("fentry/vfs_read")
int BPF_PROG(fentry_vfs_read)
{
	return inc_stats(S_READ);
}

SEC("fentry/vfs_write")
int BPF_PROG(fentry_vfs_write)
{
	return inc_stats(S_WRITE);
}

SEC("fentry/vfs_fsync")
int BPF_PROG(fentry_vfs_fsync)
{
	return inc_stats(S_FSYNC);
}

SEC("fentry/vfs_open")
int BPF_PROG(fentry_vfs_open)
{
	return inc_stats(S_OPEN);
}

SEC("fentry/vfs_create")
int BPF_PROG(fentry_vfs_create)
{
	return inc_stats(S_CREATE);
}

char LICENSE[] SEC("license") = "GPL";