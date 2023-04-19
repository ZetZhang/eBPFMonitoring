#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cpu_run_queue_length.h"
#include "cpu_run_queue_length.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "syscall_helpers.h"

static volatile bool exiting;
static void sig_handler(int sig)
{
	exiting = true;
}

struct env {
    bool verbose;
    bool per_cpu; // bpf global
    bool host;    // bpf global
    bool runqocc;
    // bool timestamps;
    time_t interval;
	pid_t pid;
	int times;
    int freq;
} env = {
	.interval = 99999999,
	.times = 99999999,
    .freq = 99,
};

const char argp_program_doc[] =
"Summarize scheduler run queue length as a histogram...\n"
"\n"
"USAGE: ebpf_program [--help] [parms]\n"
"\n"
"EXAMPLES:\n"
"    cpu_run_queu_length     # summarize scheduler run queue length as a histogram\n";

static const struct argp_option opts[] = {
	{ "Desc.", 'd', NULL, 0, "doc..." },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	// static int pos_args;
	switch (key) {
    case ARGP_KEY_ARG:
        errno = 0;
        // if (pos_args == 0) {

        // } else if (pos_args == 1) {

        // } else {

        // }
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;
static int open_and_attach_perf_event(int freq, struct bpf_program *prog, struct bpf_link *links[])
{
    // attr
    struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
    
    int fd;
    for (int i = 0; i < nr_cpus; i++) {
        if ((fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0)) < 0) {
            if (errno == ENODEV) // cpu offline
                continue;
            fprintf(stderr, "failed to init perf sampling: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        if (!(links[i] = bpf_program__attach_perf_event(prog, fd))) {
            fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
            close(fd);
            return EXIT_FAILURE;
        }
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static struct hist zero;
// static void print_runq_occupancy(struct runqlen_bpf__bss *bss) {

// }

// hist printer
static void print_linear_hists(struct cpu_run_queue_length_bpf__bss *bss) 
{
    struct hist hist;
    int i = 0;

    do {
        hist = bss->hists[i]; // per cpu hist
        bss->hists[i] = zero; // clear hist
        print_linear_hist(hist.slots, MAX_SLOTS, 0, 1, "rqlen");
    } while (env.per_cpu && ++i < nr_cpus);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

    struct bpf_link *links[MAX_CPU_NR] = {};
    struct cpu_run_queue_length_bpf *obj;
    int err;

    // argp parse
    if ((err = argp_parse(&argp, argc, argv, 0, NULL, NULL)))
        return err;

    // set print
    libbpf_set_print(libbpf_print_fn);

    // nr cpus
    if ((nr_cpus = libbpf_num_possible_cpus()) < 0) {
        printf("failed to get # of possible cpus: '%s'!\n", strerror(-nr_cpus));
        return EXIT_FAILURE;
    }
    if (nr_cpus > MAX_CPU_NR) {
        fprintf(stderr, "the number of cpu cores is too big, please increase MAX_CPU_NR's value and recompile");
        return EXIT_FAILURE;
    }

    // ensure open opts
    if ((err = ensure_core_btf(&open_opts))) {
        fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
        return EXIT_FAILURE;
    }

    // bpf open opts
    if (!(obj = cpu_run_queue_length_bpf__open_opts(&open_opts))) {
        fprintf(stderr, "failed to open BPF object\n");
        return EXIT_FAILURE;
    }

    // bpf rodata: set global data
    obj->rodata->targ_per_cpu = env.per_cpu;
	obj->rodata->targ_host = env.host;

    // bpf load
    if ((err = cpu_run_queue_length_bpf__load(obj))) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup; // clean res
    }

    // perf event
    if ((err = open_and_attach_perf_event(env.freq, obj->progs.do_sample, links)))
        goto cleanup;

    printf("[sampling run queue length...]\n");

    signal(SIGINT, sig_handler);

    for (;;) {
        sleep(env.interval); // interval
        printf("\n");

        // if (env.timestamp) {

        // }

        if (env.runqocc)
            ;
        else
            print_linear_hists(obj->bss);

        if (exiting || --env.times == 0)
            break;
    }

cleanup:
    for (int i = 0; i < nr_cpus; i++)
        bpf_link__destroy(links[i]);
    cpu_run_queue_length_bpf__destroy(obj);
    cleanup_core_btf(&open_opts);

    return err != 0;
}