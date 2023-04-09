#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include "claimed.skel.h"
#include "claimed.h"

static bool verbose = false;
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
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
    struct ring_buffer *rb = NULL;
    struct claimed_bpf *skel;
    int prog_fd;
    int err;
    
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

    // Start monitoring ring events
    while (!exiting) {
        printf("ok\n");
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

    claimed_bpf__detach(skel);

cleanup:
    ring_buffer__free(rb);
    claimed_bpf__destroy(skel);
    return err != 0;
}
