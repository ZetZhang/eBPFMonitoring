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
	// bool per_process;
	// bool per_thread;
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
"USAGE: cpu_dist [--help] [parms]\n"
"\n"
"EXAMPLES:\n"
"    cpudist              # summarize on-CPU time as a histogram\n"
"    cpudist -O           # summarize off-CPU time as a histogram\n"
"    cpudist -mT 1        # summarize off-CPU time as a histogram\n"
"    ebpf_program       # 1s summaries, milliseconds, and timestamps";

static const struct argp_option opts[] = {
	{ "offcpu", 'O', NULL, 0, "Measure off-CPU time" },
    { "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
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

    return pid_max;
}

static int print_log2_hists(int fd)
{
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
    int err, pid_ax, fd, err;

	// argp parse
	if (err = argp_parse(&argp, argc, argv, 0, NULL, NULL))
		return err;
    return 0;

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
	// obj->rodata->targ_per_process = env.per_process;
	// obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_offcpu = env.offcpu;
	obj->rodata->targ_tgid = env.pid;

    if((pid_max = get_pid_max()) < 0) {
        fprintf(stderr, "failed to get pid_max\n");
        return EXIT_FAILURE:
    }

    bpf_map__set_max_entries(obj->maps.start, pid_max);
	if (!env.per_process && !env.per_thread)
		bpf_map__set_max_entries(obj->maps.hists, 1);
	else
		bpf_map__set_max_entries(obj->maps.hists, pid_max);

	// bpf load
    if ((err = cpudist_bpf__load(obj))) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

	// bpf attach
    if ((err = cpudist_bpf__attach(obj))) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

	// signal
    signal(SIGINT, sig_handler);

	print("[Tracing %s-CPU time...]\n", env.offcpu ? "off" : "on");

    for (;;) {
        sleep(env.duration);
        printf("\n");

        if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);

            if ((err = print_log2_hists(fd)))
                break;
            if (exiting || --env.times == 0)
                break;
		}
    }

cleanup:
    cpu_dist_bpf__destroy(obj);

	return err != 0;
}
s