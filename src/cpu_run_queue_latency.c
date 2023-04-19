// cpu run queue latency
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cpu_run_queue_latency.h"
#include "cpu_run_queue_latency.skel.h"
#include "trace_helpers.h"

#define OPT_PIDNSS	1

static volatile bool exiting;
static void sig_handler(int sig)
{
	exiting = true;
}

struct env {
    time_t interval;
	pid_t pid;
	int times;
	// bool milliseconds;
	// bool per_process;
	// bool per_thread;
	// bool per_pidns;
	// bool timestamp;
	// bool verbose;
	// char *cgroupspath;
	// bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

const char argp_program_doc[] =
"ummarize run queue latency as a histogram.\n"
"\n"
"USAGE: cpu_run_queue_latency [--help] [parms]\n"
"\n"
"EXAMPLES:\n"
"    cpu_run_queue_latency       # summarize run queue latency as a histogram\n";

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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int print_log2_hists(struct bpf_map *hists)
{
    return 0;
}

int main(int argc, char const *argv[])
{
    int err;
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

    struct cpu_run_queue_latency_bpf *obj;
    int err;

    // argp parse
	if ((err = argp_parse(&argp, argc, argv, 0, NULL, NULL)))
		return err;

    // check
    // if ((env.per_thread && (env.per_process || env.per_pidns)) ||
	// 	(env.per_process && env.per_pidns)) {
	// 	fprintf(stderr, "pidnss, pids, tids cann't be used together.\n");
	// 	return EXIT_FAILURE;
	// }

    // set print
    libbpf_set_print(libbpf_print_fn);

    // bpf open
    if (!(obj = cpu_run_queue_latency_bpf__open())) {
        fprintf(stderr, "failed to open BPF object\n");
		return EXIT_FAILURE;
    }

    // bpf rodata: set global data
    

cleanup:

    return 0;
}
