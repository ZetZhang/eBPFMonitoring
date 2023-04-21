#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "compat.h"
#include "mem_oomkill.skel.h"
#include "mem_oomkill.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

struct env {
    time_t interval;
	pid_t pid;
	int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

const char argp_program_doc[] =
"oomkill...\n"
"\n"
"USAGE: ebpf_program [--help]\n"
"\n"
"EXAMPLES:\n"
"    oomkill               # trace OOM kills\n";

static const struct argp_option opts[] = {
	{ "Desc.", 'd', NULL, 0, "doc..." },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
    {}
};

static bool verbose = false;
static volatile sig_atomic_t exiting = 0;
static void sig_handler(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct data_t *e = data;
    FILE *f;
    struct tm *tm;
    char buf[256];
    char ts[32];
    time_t t;
    int n = 0;

    if ((f = fopen("/proc/loadavg", "r"))) {
        memset(buf, 0, sizeof(buf));
        n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
    }
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (n)
		printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld pages, loadavg: %s",
			ts, e->fpid, e->fcomm, e->tpid, e->tcomm, e->pages, buf);
	else
		printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld pages\n",
			ts, e->fpid, e->fcomm, e->tpid, e->tcomm, e->pages);

    return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
        verbose = true;
		break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char *argv[]) 
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
    struct bpf_buffer *buf = NULL;
    struct mem_oomkill_bpf *obj;
    int err;

    // argp parse
	if ((err = argp_parse(&argp, argc, argv, 0, NULL, NULL)))
		return err;

    // set print
    libbpf_set_print(libbpf_print_fn);

    // core btf
    if ((err = ensure_core_btf(&open_opts))) {
        fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return EXIT_FAILURE;
    }

    // bpf open opts
    if (!(obj = mem_oomkill_bpf__open_opts(&open_opts))) {
        fprintf(stderr, "failed to load and open BPF object\n");
		return EXIT_FAILURE;
    }

    // new buffer
    if (!(buf = bpf_buffer__new(obj->maps.events, obj->maps.heap))) {
		err = -errno;
		fprintf(stderr, "failed to create ring/perf buffer: %d\n", err);
        goto cleanup;
    }

    // bpf load
    if ((err = mem_oomkill_bpf__load(obj))) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // bpf attach
    if ((err = mem_oomkill_bpf__attach(obj))) {
		fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    // open buffer
    if ((err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL))) {
		fprintf(stderr, "failed to open ring/perf buffer: %d\n", err);
        goto cleanup;
    }

    // signal
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %d\n", err);
		err = 1;
        goto cleanup;
    }

    printf("[Tracing OOM kills...]\n");

    for (;;) {
        
    }

cleanup:
    bpf_buffer__free(buf);
    mem_oomkill_bpf__destroy(obj);
    cleanup_core_btf(&open_opts);

    return 0;
}