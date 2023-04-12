#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include "claimed.skel.h"
#include "claimed.h"

static bool verbose = false;
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct data_t *e = data;

    printf("1: %d, 2: %d, 3: %d\n", e->cpu, e->ts, e->len);

    return 0;
}

int main(int argc, char *argv[]) {
    int freq = 99, pid = -1, cpu = -1;
    struct ring_buffer *rb = NULL;
    struct perf_event_attr attr;
    // struct bpf_link **links = NULL;
    struct bpf_link *link = NULL;
    struct claimed_bpf *skel;
	int num_cpus;
	int *pefds = NULL, pefd;
    int prog_fd;
    int err, i;
    
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);  
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    /* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

    // Create a new instance of the skeleton
    skel = claimed_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skel\n");
        return 1;
    }

    num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		return 1;
	}

    // Load and verify the BPF program
    err = claimed_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load skel: %d\n", err);
        goto cleanup;
    }

    // Attach the BPF program to the ring event
    prog_fd = claimed_bpf__attach(skel);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", prog_fd);
        goto cleanup;
    }

    /* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL/*&rb_opts*/);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

    pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++)
		pefds[i] = -1;

    link = calloc(1, sizeof(struct bpf_link *));

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
	attr.sample_freq = freq;
	attr.sample_period = 0;

    pefd = perf_event_open(&attr, pid, cpu, -1, 0);
    // if (pefd < 0) {
    //     fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
    //     goto cleanup;
	// }
    link = bpf_program__attach_perf_event(skel->progs.claimed_event, pefd);
    if (!link) {
        err = -1;
        goto cleanup;
    }

    // for (cpu = 0; cpu < num_cpus; cpu++) {
	// 	/* Set up performance monitoring on a CPU/Core */
	// 	pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
	// 	if (pefd < 0) {
	// 		fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
	// 		goto cleanup;
	// 	}
	// 	pefds[cpu] = pefd;

	// 	/* Attach a BPF program on a CPU */
	// 	links[cpu] = bpf_program__attach_perf_event(skel->progs.claimed_event, pefd);
	// 	if (!links[cpu]) {
	// 		err = -1;
	// 		goto cleanup;
	// 	}
	// }

    // Start monitoring ring events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        // err = claimed_bpf__attach(skel);
        if (err == -EINTR) {
			err = 0;
			break;
		}
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    claimed_bpf__destroy(skel);
    return err != 0;
}
