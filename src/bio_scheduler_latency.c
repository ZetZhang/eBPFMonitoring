// I/O scheduler latency
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>

#include "blk_types.h"
#include "bio_scheduler_latency.h"
#include "bio_scheduler_latency.skel.h"
#include "trace_helpers.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct env {
    char *disk;
	time_t interval;
	int times;
	bool timestamp;
	bool queued;
	bool per_disk;
	bool per_flag;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
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
"Summarize block device I/O latency as a histogram.\n"
"\n"
"USAGE: bio_scheduler_latency [--help] [parms]\n"
"\n"
"EXAMPLES:\n"
"    bio_scheduler_latency         # summarize block I/O latency as a histogram\n";

static const struct argp_option opts[] = {
	{ "Desc.", 'd', NULL, 0, "doc..." },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	// static int pos_args;

	switch (key) {
	case 'd':
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

static void print_cmd_flags(int cmd_flags)
{
	static struct { int bit; const char *str; } flags[] = {
		{ REQ_NOWAIT, "NoWait-" },
		{ REQ_BACKGROUND, "Background-" },
		{ REQ_RAHEAD, "ReadAhead-" },
		{ REQ_PREFLUSH, "PreFlush-" },
		{ REQ_FUA, "FUA-" },
		{ REQ_INTEGRITY, "Integrity-" },
		{ REQ_IDLE, "Idle-" },
		{ REQ_NOMERGE, "NoMerge-" },
		{ REQ_PRIO, "Priority-" },
		{ REQ_META, "Metadata-" },
		{ REQ_SYNC, "Sync-" },
	};
	static const char *ops[] = {
		[REQ_OP_READ] = "Read",
		[REQ_OP_WRITE] = "Write",
		[REQ_OP_FLUSH] = "Flush",
		[REQ_OP_DISCARD] = "Discard",
		[REQ_OP_SECURE_ERASE] = "SecureErase",
		[REQ_OP_ZONE_RESET] = "ZoneReset",
		[REQ_OP_WRITE_SAME] = "WriteSame",
		[REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll",
		[REQ_OP_WRITE_ZEROES] = "WriteZeroes",
		[REQ_OP_ZONE_OPEN] = "ZoneOpen",
		[REQ_OP_ZONE_CLOSE] = "ZoneClose",
		[REQ_OP_ZONE_FINISH] = "ZoneFinish",
		[REQ_OP_SCSI_IN] = "SCSIIn",
		[REQ_OP_SCSI_OUT] = "SCSIOut",
		[REQ_OP_DRV_IN] = "DrvIn",
		[REQ_OP_DRV_OUT] = "DrvOut",
	};
	int i;

	printf("flags = ");

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		if (cmd_flags & flags[i].bit)
			printf("%s", flags[i].str);
	}

	if ((cmd_flags & REQ_OP_MASK) < ARRAY_SIZE(ops))
		printf("%s", ops[cmd_flags & REQ_OP_MASK]);
	else
		printf("Unknown");
}

static int print_log2_hists(struct bpf_map *hists, struct partitions *partitions)
{
    struct hist_key lookup_key = { .cmd_flags = -1 }, next_key;
    const char *units = env.milliseconds ? "msecs" : "usecs";
	const struct partition *partition;
	int err, fd = bpf_map__fd(hists);
	struct hist hist;

    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        if ((err = bpf_map_lookup_elem(fd, &next_key, &hist)) < 0) {
            fprintf(stderr, "failed to lookup hist: %d\n", err);
            return EXIT_FAILURE;
        }
        if (env.per_disk) {
            partition = partitions__get_by_dev(partitions, next_key.dev);
            printf("\ndisk = %s\t", partition ? partition->name : "Unknown");
        }
        if (env.per_flag)
			print_cmd_flags(next_key.cmd_flags);
		printf("\n");
		print_log2_hist(hist.slots, MAX_SLOTS, units);
        lookup_key = next_key;
    }

    lookup_key.cmd_flags = -1;
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        if ((err = bpf_map_delete_elem(fd, &next_key)) < 0) {
            fprintf(stderr, "failed to cleanup hist : %d\n", err);
            return EXIT_FAILURE;
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
    struct bio_scheduler_latency_bpf *obj;
    struct partitions *partitions = NULL;
    const struct partition *partition;
    struct tm *tm;
    char ts[32];
    time_t t;

    int err;

	// argp parse
	if ((err = argp_parse(&argp, argc, argv, 0, NULL, NULL)))
		return err;

	// set print
	libbpf_set_print(libbpf_print_fn);

    // bpf open
    if (!(obj = bio_scheduler_latency_bpf__open())) {
        fprintf(stderr, "failed to open BPF object\n");
        return EXIT_FAILURE;
    }

    if (!(partitions = partitions__load())) {
        fprintf(stderr, "failed to load partitions info\n");
        goto cleanup;
    }

    // set bpf global
    if (env.disk) {
        if (!(partition = partitions__get_by_name(partitions, env.disk))) {
            fprintf(stderr, "invaild partition name: not exist\n");
            goto cleanup;
        }
        obj->rodata->filter_dev = true;
        obj->rodata->targ_dev = partition->dev;
    }
    obj->rodata->targ_per_disk = env.per_disk;
	obj->rodata->targ_per_flag = env.per_flag;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_queued = env.queued;
	
    if (probe_tp_btf("block_rq_insert")) {
		bpf_program__set_autoload(obj->progs.block_rq_insert, false);
		bpf_program__set_autoload(obj->progs.block_rq_issue, false);
		bpf_program__set_autoload(obj->progs.block_rq_complete, false);
		if (!env.queued)
			bpf_program__set_autoload(obj->progs.block_rq_insert_btf, false);
	} else {
		bpf_program__set_autoload(obj->progs.block_rq_insert_btf, false);
		bpf_program__set_autoload(obj->progs.block_rq_issue_btf, false);
		bpf_program__set_autoload(obj->progs.block_rq_complete_btf, false);
		if (!env.queued)
			bpf_program__set_autoload(obj->progs.block_rq_insert, false);
	}

    // bpf load
    if ((err = bio_scheduler_latency_bpf__load(obj))) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

	// bpf attach
    if ((err = bio_scheduler_latency_bpf__attach(obj))) {
        fprintf(stderr, "failed to attach BPF object: %d\n", err);
        goto cleanup;
    }

	// signal
    signal(SIGINT, sig_handler);

	printf("[Tracing block device I/O...]\n");

    for (;;) {
        sleep(env.interval);
        printf("\n");

        if (env.timestamp) {
            time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
        }

        if ((err = print_log2_hists(obj->maps.hists, partitions)))
            break;
        
        if (exiting || --env.times == 0)
            break;
    }

cleanup:
    bio_scheduler_latency_bpf__destroy(obj);
	partitions__free(partitions);

	return err != 0;
}
