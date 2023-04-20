// cache reference and miss
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cpu_hit_situation.h"
#include "cpu_hit_situation.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

struct env {
    int sample_period;
    time_t duration;
    bool verbose;
    bool per_thread;
} env = {
    .sample_period = 100,
    .duration = 10,
};

static volatile bool exiting;
static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

const char argp_program_doc[] =
"Summarize cache references and misses by PID.\n"
"\n"
"USAGE: cpu_hit_situation [--help] [parms]\n"
"\n"
"EXAMPLES:\n"
"    llcstat\n";

static const struct argp_option opts[] = {
	{ "Desc.", 'd', NULL, 0, "doc..." },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case ARGP_KEY_ARG:

		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;
static int open_and_attach_perf_event(__u64 config, int period, struct bpf_program *prog, struct bpf_link *links[])
{
    struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.freq = 0,
		.sample_period = period,
		.config = config,
	};
    int fd;

    for (int i = 0; i < nr_cpus; i++) {
		if ((fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0)) < 0) {
			if (errno == ENODEV) // offline
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
			close(fd);
			return EXIT_FAILURE;
		}
	}
    return 0;
}

static void print_map(struct bpf_map *map)
{
    __u64 total_ref = 0, total_miss = 0, total_hit, hit;
    __u32 pid, cpu, tid;
    struct key_info lookup_key = { .cpu = -1 }, next_eky;

    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		if ((err = bpf_map_lookup_elem(fd, &next_key, &info)) < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return;
		}
		hit = info.ref > info.miss ? info.ref - info.miss : 0;
		cpu = next_key.cpu;
		pid = next_key.pid;
		tid = next_key.tid;
		printf("%-8u ", pid);
		if (env.per_thread)
			printf("%-8u ", tid);
		printf("%-16s %-4u %12llu %12llu %6.2f%%\n",
			info.comm, cpu, info.ref, info.miss, info.ref > 0 ? hit * 1.0 / info.ref * 100 : 0);
		total_miss += info.miss;
		total_ref += info.ref;
		lookup_key = next_key;
    }
    total_hit = total_ref > total_miss ? total_ref - total_miss : 0;
	printf("Total References: %llu Total Misses: %llu Hit Rate: %.2f%%\n",
		total_ref, total_miss, total_ref > 0 ? total_hit * 1.0 / total_ref * 100 : 0);

	lookup_key.cpu = -1;
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        if ((err = bpf_map_delete_elem(fd, &next_key)) < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return;
		}
		lookup_key = next_key;
    }
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
    struct cpu_hit_situation_bpf *obj;
    struct bpf_link **rlinks = NULL;
    struct **mlinks = NULL;
    int err;

    // argp parse
	if (err = argp_parse(&argp, argc, argv, 0, NULL, NULL))
		return err;

    // set print
	libbpf_set_print(libbpf_print_fn);

    if ((nr_cpus = libbpf_num_possible_cpus()) < 0) {
        fprintf(stderr, "failed to get # of possible cpus: '%s'!\n", strerror(-nr_cpus));
        return EXIT_FAILURE;
    }

    // alloc
    mlinks = calloc(nr_cpus, sizeof(*mlinks));
	rlinks = calloc(nr_cpus, sizeof(*rlinks));
    if (!mlinks || !rlinks) {
        fprintf(stderr, "failed to alloc mlinks or rlinks\n");
        return EXIT_FAILURE;
    }

    // core btf
    if ((err = ensure_core_btf(&open_opts))) {
        fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
        return EXIT_FAILURE;
    }

    // bpf open opts
    if (!(obj = cpu_hit_situation_bpf__open_opts(&open_opts))) {
        fprintf(stderr, "failed to open and/or load BPF object\n");
        goto cleanup;
    }

    // bpf set global
    obj->rodata->targ_per_thread = env.per_thread;

    // bpf load
    if ((err = cpu_hit_situation_bpf__load(obj))) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // attach perf event
    if (open_and_attach_perf_event(PERF_COUNT_HW_CACHE_MISSES, env.sample_period, obj->progs.on_cache_miss, mlinks))
		goto cleanup;
	if (open_and_attach_perf_event(PERF_COUNT_HW_CACHE_REFERENCES, env.sample_period, obj->progs.on_cache_ref, rlinks))
		goto cleanup;

    printf("[Running for %ld seconds or Hit Ctrl-C to end.]\n", env.duration);

    // signal
    signal(SIGINT, sig_handler);

    // duration sleep
    sleep(env.duration);

    printf("%-8s ", "PID");
	if (env.per_thread) {
		printf("%-8s ", "TID");
	}
	printf("%-16s %-4s %12s %12s %7s\n",
		"NAME", "CPU", "REFERENCE", "MISS", "HIT%");

    print_map(obj->maps.infos);

cleanup:
    for (i = 0; i < nr_cpus; i++) {
		bpf_link__destroy(mlinks[i]);
		bpf_link__destroy(rlinks[i]);
	}
    free(mlinks);
    free(rlinks);
    cpu_hit_situation_bpf__destroy(obj);
    cleanup_core_btf(&open_opts);
    
    return err != 0;
}
