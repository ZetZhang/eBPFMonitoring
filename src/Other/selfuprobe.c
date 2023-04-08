#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "selfuprobe.skel.h"

static int libbpf_output(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memlock_limit(void)
{
    int32_t ret = 0;
    struct rlimit rl = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    ret = setrlimit(RLIMIT_MEMLOCK, &rl);
    if (0 != ret)
    {
        printf("failed to increase RLIMIT_MEMLOCK limit\n");
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    int32_t ret = 0;
    struct selfuprobe_bpf *skel = NULL;
    long func_offset = 0x1139;

    libbpf_set_print(libbpf_output);

    bump_memlock_limit();

    skel = selfuprobe_bpf__open_and_load();
    if (NULL == skel)
    {
        printf("failed to open and load bpf skeleton\n");
        return -1;
    }

    skel->links.uprobe = bpf_program__attach_uprobe(skel->progs.uprobe, false, -1, "/home/ichheit/ich/eBPFMonitoring/src/Other/test", func_offset);
    ret = libbpf_get_error(skel->links.uprobe);
    if (0 != ret)
    {
        printf("failed to attach uprobe:%d\n", ret);
        goto exit;
    }

    skel->links.uretprobe = bpf_program__attach_uprobe(skel->progs.uretprobe, true, -1, "/home/ichheit/ich/eBPFMonitoring/src/Other/test", func_offset);
    ret = libbpf_get_error(skel->links.uretprobe);
    if (0 != ret)
    {
        printf("failed to attach uretprobe:%d\n", ret);
        goto exit;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
               "to see output of the BPF programs.\n");

    while (1)
    {
        printf("I am alive ...\n");
        sleep(1);
    }

    return 0;

exit:
    selfuprobe_bpf__destroy(skel);

    return -1;
}
