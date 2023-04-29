#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>

#include "vfs_iostat.h"
#include "vfs_iostat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

struct env {
	int interval;
	int count;
	bool verbose;
} env = {
	.interval = 1,
};

static const char *strftime_now(char *s, size_t max, const char *format)
{
	struct tm *tm;
	time_t t;

	t = time(NULL);
	tm = localtime(&t);
	if (tm == NULL) {
		fprintf(stderr, "localtime: %s\n", strerror(errno));
		return "<failed>";
	}
	if (strftime(s, max, format, tm) == 0) {
		fprintf(stderr, "strftime error\n");
		return "<failed>";
	}
	return s;
}

static const char *stat_types_names[] = {
	[S_READ] = "READ",
	[S_WRITE] = "WRITE",
	[S_FSYNC] = "FSYNC",
	[S_OPEN] = "OPEN",
	[S_CREATE] = "CREATE",
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

const char argp_program_doc[] =
"Count some VFS calls.\n"
"\n"
"USAGE: vfs_iostat [--help] [parms]\n"
"\n"
"EXAMPLES:\n"
	"    vfs_iostat      # interval 1 second\n"
	"    vfs_iostat 5 3  # interval 5 seconds, 3 output lines\n";

static char args_doc[] = "[interval [count]]";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long interval;
	long count;

	switch (key) {
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			errno = 0;
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0 || interval > INT_MAX) {
				fprintf(stderr, "invalid interval: %s\n", arg);
				argp_usage(state);
			}
			env.interval = interval;
			break;
		case 1:
			errno = 0;
			count = strtol(arg, NULL, 10);
			if (errno || count < 0 || count > INT_MAX) {
				fprintf(stderr, "invalid count: %s\n", arg);
				argp_usage(state);
			}
			env.count = count;
			break;
		default:
			argp_usage(state);
			break;
		}
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

static void print_header(void)
{
	printf("%-8s  ", "TIME");
	for (int i = 0; i < S_MAXSTAT; i++)
		printf(" %6s/s", stat_types_names[i]);
	printf("\n");
}

static void print_and_reset_stats(__u64 stats[S_MAXSTAT])
{
	char s[16];

	printf("%-8s: ", strftime_now(s, sizeof(s), "%H:%M:%S"));
	for (int i = 0; i < S_MAXSTAT; i++) {
		__u64 val = __atomic_exchange_n(&stats[i], 0, __ATOMIC_RELAXED);
		printf(" %8llu", val / env.interval);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
        .args_doc = args_doc,
	};
    struct vfs_iostat_bpf *skel;
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

	// bpf open
    if (!(skel = vfs_iostat_bpf__open())) {
        fprintf(stderr, "failed to open BPF skelect\n");
        return EXIT_FAILURE;
    }

	// set bpf global
    if (fentry_can_attach("vfs_read", NULL)) {
		bpf_program__set_autoload(skel->progs.kprobe_vfs_read, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_write, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_fsync, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_open, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_create, false);
	} else {
		bpf_program__set_autoload(skel->progs.fentry_vfs_read, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_write, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_fsync, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_open, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_create, false);
	}

	// bpf load
    if ((err = vfs_iostat_bpf__load(skel))) {
        fprintf(stderr, "failed to load BPF skelect: %d\n", err);
        goto cleanup;
    }

    if (!skel->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	// bpf attach
    if ((err = vfs_iostat_bpf__attach(skel))) {
        fprintf(stderr, "failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
    }

    print_header();
	do {
		sleep(env.interval);
		print_and_reset_stats(skel->bss->stats);
	} while (!env.count || --env.count);
    
cleanup:
    vfs_iostat_bpf__destroy(skel);
    cleanup_core_btf(&open_opts);

	return err != 0;
}
