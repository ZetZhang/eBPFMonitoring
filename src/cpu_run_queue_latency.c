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
	bool verbose;
	bool milliseconds;
	bool per_process;
	bool per_thread;
	bool per_pidns;
	bool timestamp;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

const char argp_program_doc[] =
"Summarize run queue latency as a histogram.\n"
"\n"
"USAGE: cpu_run_queue_latency [--help] [interval] [count] [-T] [-m] [--pidnss] [-L] [-P] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    cpu_run_queue_latency  			# summarize run queue latency as a histogram\n"
"    cpu_run_queue_latency 1 10    		# print 1 second summaries, 10 times\n"
"    cpu_run_queue_latency -mT 1   		# 1s summaries, milliseconds, and timestamps\n"
"    cpu_run_queue_latency -P     		# show each PID separately\n"
"    cpu_run_queue_latency -p 200  		# trace PID 200 only\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "pidnss", OPT_PIDNSS, NULL, 0, "Print a histogram per PID namespace" },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID" },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case OPT_PIDNSS:
		env.per_pidns = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'L':
		env.per_thread = true;
		break;
	case 'P':
		env.per_process = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
    case ARGP_KEY_ARG:
        errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr, "unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	case ARGP_KEY_END:
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
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
    const char *units = env.milliseconds ? "msecs" : "usecs";
	int err, fd = bpf_map__fd(hists);
	__u32 lookup_key = -2, next_key;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n", next_key, hist.comm);
		else if (env.per_thread)
			printf("\ntid = %d %s\n", next_key, hist.comm);
		else if (env.per_pidns)
			printf("\npidns = %u %s\n", next_key, hist.comm);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -2;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}
	return 0;
}

int main(int argc, char *argv[])
{
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

    struct cpu_run_queue_latency_bpf *obj;
	struct tm *tm;
	time_t t;
	char ts[32];
    int err;

    // argp parse
	if ((err = argp_parse(&argp, argc, argv, 0, NULL, NULL)))
		return err;

    // check
    if ((env.per_thread && (env.per_process || env.per_pidns)) || (env.per_process && env.per_pidns)) {
		fprintf(stderr, "pidnss, pids, tids cann't be used together.\n");
		return EXIT_FAILURE;
	}

    // set print
    libbpf_set_print(libbpf_print_fn);

    // bpf open
    if (!(obj = cpu_run_queue_latency_bpf__open())) {
        fprintf(stderr, "failed to open BPF object\n");
		return EXIT_FAILURE;
    }

    // bpf rodata: set global data
    obj->rodata->targ_per_process = env.per_process;
	obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_per_pidns = env.per_pidns;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_tgid = env.pid;

	// set auto load
	if (probe_tp_btf("sched_wakeup")) {
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.handle_sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.handle_sched_switch, false);
	} else {
		bpf_program__set_autoload(obj->progs.sched_wakeup, false);
		bpf_program__set_autoload(obj->progs.sched_wakeup_new, false);
		bpf_program__set_autoload(obj->progs.sched_switch, false);
	}

	// bpf load
	if ((err = cpu_run_queue_latency_bpf__load(obj))) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	// bpf attach
	if ((err = cpu_run_queue_latency_bpf__attach(obj))) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("[sampling run queue latency...]\n");

	// signal
	signal(SIGINT, sig_handler);

	// main poll
	for (;;) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		if ((err = print_log2_hists(obj->maps.hists)))
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	cpu_run_queue_latency_bpf__destroy(obj);

    return err != 0;
}
