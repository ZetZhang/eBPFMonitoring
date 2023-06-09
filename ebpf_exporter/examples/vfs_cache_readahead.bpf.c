#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "vfs_cache_readahead.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	10240

struct hist hist = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} in_readahead SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct page *);
	__type(value, u64);
} birth SEC(".maps");

SEC("fentry/do_page_cache_ra")
int BPF_PROG(do_page_cache_ra)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 one = 1;

	bpf_map_update_elem(&in_readahead, &pid, &one, 0);
	return 0;
}

SEC("fexit/do_page_cache_ra")
int BPF_PROG(do_page_cache_ra_ret)
{
	u32 pid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&in_readahead, &pid);
	return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(mark_page_accessed, struct page *page)
{
	u64 *tsp, slot, ts = bpf_ktime_get_ns();
	s64 delta;

	if (!(tsp = bpf_map_lookup_elem(&birth, &page)))
		return 0;
	if ((delta = (s64)(ts - *tsp)) < 0)
		goto update_and_cleanup;
	if ((slot = log2l(delta / 1000000U)) >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist.slots[slot], 1);

update_and_cleanup:
	__sync_fetch_and_add(&hist.unused, -1);
	bpf_map_delete_elem(&birth, &page);

	return 0;
}

SEC("fexit/__page_cache_alloc")
int BPF_PROG(page_cache_alloc_ret, gfp_t gfp, struct page *ret)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts;

	if (!bpf_map_lookup_elem(&in_readahead, &pid))
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&birth, &ret, &ts, 0);
	__sync_fetch_and_add(&hist.unused, 1);
	__sync_fetch_and_add(&hist.total, 1);

	return 0;
}


char LICENSE[] SEC("license") = "GPL";