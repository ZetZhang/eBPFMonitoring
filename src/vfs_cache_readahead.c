// vfs cache readahead
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "vfs_cache_readahead.h"
#include "vfs_cache_readahead.skel.h"
#include "trace_helpers.h"

struct env {
    int duration;
	bool verbose;
} env = {
	.duration = -1
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
"Show fs automatic read-ahead usage.\n"
"\n"
"USAGE: readahead [--help] [-d DURATION]\n"
"\n"
"EXAMPLES:\n"
"    readahead              # summarize on-CPU time as a histogram\n"
"    readahead -d 10        # trace for 10 seconds only\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
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

static int readahead__set_attach_target(struct bpf_program *prog)
{
    int err;

    if (!(err = bpf_program__set_attach_target(prog, 0, "do_page_cache_ra")))
        return 0;
    if (!(err = bpf_program__set_attach_target(prog, 0, "__do_page_cache_readahead")))
        return 0;

    fprintf(stderr, "failed to set attach target for %s: %s\n", bpf_program__name(prog), strerror(-err));
    return err;
}

int main(int argc, char *argv[])
{
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
    struct vfs_cache_readahead_bpf *obj;
    struct hist *histp;
    int err;

    // argp parse
	if (err = argp_parse(&argp, argc, argv, 0, NULL, NULL))
		return err;

    // set print
	libbpf_set_print(libbpf_print_fn);

    // bpf open
    if (!(obj = readahead_bpf__open())) {
		fprintf(stderr, "failed to open BPF object\n");
		return EXIT_FAILURE;
    }

    // bpf set attach
    // Starting from v5.10-rc1 (8238287), __do_page_cache_readahead has 
    // renamed to do_page_cache_ra. So we specify the function dynamically.
    if ((err = readahead__set_attach_target(obj->progs.do_page_cache_ra)))
        goto cleanup;
    if ((err = readahead__set_attach_target(obj->progs.do_page_cache_ra_ret)))
        goto cleanup;

    // bpf load
    if ((err = readahead_bpf__load(obj))) {
        fprintf(stderr, "failed to load BPF object\n");
        goto cleanup;
    }

    // bss check
    if (!obj->bss) {
        fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
        goto cleanup;
    }

    // bpf attach
    if ((err = readahead_bpf__attach(obj))) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    // signal
    signal(SIGINT, sig_handler);

    printf("[Tracing fs read-ahead ...]\n");

    sleep(env.duration);
	printf("\n");

    histp = &obj->bss->hist;

    printf("Readahead unused/total pages: %d/%d\n", histp->unused, histp->total);
	print_log2_hist(histp->slots, MAX_SLOTS, "msecs");

cleanup:
    vfs_cache_readahead_bpf__destroy(obj);

    return 0;
}
