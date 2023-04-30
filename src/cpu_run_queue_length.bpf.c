#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "cpu_run_queue_length.h"

const volatile bool targ_per_cpu = false;
const volatile bool targ_host = false;

struct hist hists[MAX_CPU_NR] = {};

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	struct task_struct *task;
	struct hist *hist;
	u64 slot, cpu = 0;

	task = (struct task_struct *)bpf_get_current_task();
	if (targ_host)
		slot = BPF_CORE_READ(task, se.cfs_rq, rq, nr_running);
	else
		slot = BPF_CORE_READ(task, se.cfs_rq, nr_running);
	if (slot > 0)
		slot--;
	if (targ_per_cpu) {
		cpu = bpf_get_smp_processor_id();
		if (cpu >= MAX_CPU_NR)
			return 0;
	}
	hist = &hists[cpu];
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	if (targ_per_cpu)
		hist->slots[slot]++;
	else
		__sync_fetch_and_add(&hist->slots[slot], 1);
	return 0;
}

// static int increment_map(void *map, void *key, u64 increment)  {
//     u64 zero = 0, *count = bpf_map_lookup_elem(map, key);
//     if (!count) {
//         bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
//         count = bpf_map_lookup_elem(map, key);
//         if (!count) {
//             return 0;
//         }
//     }

//     __sync_fetch_and_add(count, increment);

//     return *count;
// }


// static int trace_event(void *map, u32 cpu, u64 sample_period)
// {
// 	increment_map(map, &cpu, sample_period);
// }

// SEC("perf_event/type=1,config=0,frequency=1")
// int do_sample_exporter(struct bpf_perf_event_data *ctx)
// {
// }

char LICENSE[] SEC("license") = "GPL";