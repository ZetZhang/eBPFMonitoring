#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "cpu_dist.h"
#include "cpu_dist.skel.h"
#include "trace_helpers.h"

struct env {
    time_t interval;
	pid_t pid;
	int times;
	bool offcpu;
	bool timestamp;
	bool per_process;
	bool per_thread;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
	.pid = -1,
	.times = 99999999,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting;
static void sig_handler(int sig)
{
	exiting = true;
}

const char argp_program_doc[] =
"Summarize on-CPU time per task as a histogram.\n"
"\n"
"USAGE: cpu_dist [--help] [interval] [count] [-O] [-T] [-m] [-P] [-L] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    cpu_dist              # summarize on-CPU time as a histogram\n"
"    cpu_dist 1 10         # print 1 second summaries, 10 times\n"
"    cpu_dist -O           # summarize off-CPU time as a histogram\n"
"    cpu_dist -mT 1        # 1s summaries, milliseconds, and timestamps\n"
"    cpu_dist -P           # show each PID separately\n"
"    cpu_dist -p 200       # trace PID 200 only\n";

static const struct argp_option opts[] = {
	{ "offcpu", 'O', NULL, 0, "Measure off-CPU time" },
    { "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
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
	case 'O':
		env.offcpu = true;
		break;
    case 'm':
		env.milliseconds = true;
		break;
    case 'T':
		env.timestamp = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'P':
		env.per_process = true;
		break;
	case 'L':
		env.per_thread = true;
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
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	case ARGP_KEY_END:
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

static int get_pid_max(void)
{
    int pid_max;
	FILE *f;

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d\n", &pid_max) != 1)
		pid_max = -1;
	fclose(f);
	return pid_max;
}

static int print_log2_hists(int fd)
{
    char *units = env.milliseconds ? "msecs" : "usecs";
	__u32 lookup_key = -2, next_key;
	struct hist hist;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n", next_key, hist.comm);
		if (env.per_thread)
			printf("\ntid = %d %s\n", next_key, hist.comm);
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
    struct cpu_dist_bpf *obj;
    struct tm *tm;
    char ts[32];
    time_t t;
    int err, pid_max, fd;

	// argp parse
	if ((err = argp_parse(&argp, argc, argv, 0, NULL, NULL)))
		return err;

	// set print
	libbpf_set_print(libbpf_print_fn);

	// bpf open
    if (!(obj = cpu_dist_bpf__open())) {
        fprintf(stderr, "failed to open BPF object\n");
        return EXIT_FAILURE;
    }    
    
    if (probe_tp_btf("sched_switch"))
		bpf_program__set_autoload(obj->progs.sched_switch_tp, false);
	else
		bpf_program__set_autoload(obj->progs.sched_switch_btf, false);

	// set bpf global
	obj->rodata->targ_per_process = env.per_process;
	obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_offcpu = env.offcpu;
	obj->rodata->targ_tgid = env.pid;

    if((pid_max = get_pid_max()) < 0) {
        fprintf(stderr, "failed to get pid_max\n");
        return EXIT_FAILURE;
    }

    bpf_map__set_max_entries(obj->maps.start, pid_max);
	if (!env.per_process && !env.per_thread)
		bpf_map__set_max_entries(obj->maps.hists, 1);
	else
		bpf_map__set_max_entries(obj->maps.hists, pid_max);

	// bpf load
    if ((err = cpu_dist_bpf__load(obj))) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

	// bpf attach
    if ((err = cpu_dist_bpf__attach(obj))) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

	fd = bpf_map__fd(obj->maps.hists);

	// signal
    signal(SIGINT, sig_handler);

	printf("[Tracing %s-CPU time...]\n", env.offcpu ? "off" : "on");

    for (;;) {
        sleep(env.interval);
        printf("\n");

        if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		if ((err = print_log2_hists(fd)))
			break;
		if (exiting || --env.times == 0)
			break;
    }

cleanup:
    cpu_dist_bpf__destroy(obj);

	return err != 0;
}