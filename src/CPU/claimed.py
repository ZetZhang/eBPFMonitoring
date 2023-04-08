#!/usr/bin/env python
from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
import argparse
import multiprocessing
from os import getpid, system, open, close, dup, unlink, O_WRONLY
from tempfile import NamedTemporaryFile

# arguments
examples = """examples:
    ./cpuunclaimed            # sample and calculate unclaimed idle CPUs,
                              # output every 1 second (default)
    ./cpuunclaimed 5 10       # print 5 second summaries, 10 times
    ./cpuunclaimed -T 1       # 1s summaries and timestamps
    ./cpuunclaimed -j         # raw dump of all samples (verbose), CSV
"""
parser = argparse.ArgumentParser(
    description="Sample CPU run queues and calculate unclaimed idle CPU",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-j", "--csv", action="store_true",
    help="print sample summaries (verbose) as comma-separated values")
parser.add_argument("-J", "--fullcsv", action="store_true",
    help="print sample summaries with extra fields: CPU sample offsets")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("interval", nargs="?", default=-1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
frequency = 99
dobind = 1
wakeup_hz = 10                      # frequency to read buffers
wakeup_s = float(1) / wakeup_hz
ncpu = multiprocessing.cpu_count()  # assume all are online
debug = 0

def check_runnable_weight_field():
    bpf_check_text = """
#include <linux/sched.h>
unsigned long dummy(struct sched_entity *entity)
{
    return entity->runnable_weight;
}
"""

    # Get a temporary file name
    tmp_file = NamedTemporaryFile(delete=False)
    tmp_file.close();

    # Duplicate and close stderr (fd = 2)
    old_stderr = dup(2)
    close(2)

    # Open a new file, should get fd number 2
    # This will avoid printing llvm errors on the screen
    fd = open(tmp_file.name, O_WRONLY)
    try:
        t = BPF(text=bpf_check_text)
        success_compile = True
    except:
        success_compile = False

    # Release the fd 2, and next dup should restore old stderr
    close(fd)
    dup(old_stderr)
    close(old_stderr)

    # remove the temporary file and return
    unlink(tmp_file.name)
    return success_compile


# process arguments
if args.fullcsv:
    args.csv = True
if args.csv:
    interval = 0.2
if args.interval != -1 and (args.fullcsv or args.csv):
    print("ERROR: cannot use interval with either -j or -J. Exiting.")
    exit()
if args.interval == -1:
    args.interval = "1"
interval = float(args.interval)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct data_t {
    u64 ts;
    u64 cpu;
    u64 len;
};

BPF_PERF_OUTPUT(events);

// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    RUNNABLE_WEIGHT_FIELD
    unsigned int nr_running, h_nr_running;
};

int do_perf_event(struct bpf_perf_event_data *ctx)
{
    int cpu = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_ns();

    /*
     * Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
     * unstable interface and may need maintenance. Perhaps a future version
     * of BPF will support task_rq(p) or something similar as a more reliable
     * interface.
     */
    unsigned int len = 0;
    struct task_struct *task = NULL;
    struct cfs_rq_partial *my_q = NULL;
    task = (struct task_struct *)bpf_get_current_task();
    my_q = (struct cfs_rq_partial *)task->se.cfs_rq;
    len = my_q->nr_running;

    struct data_t data = {.ts = now, .cpu = cpu, .len = len};
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

if check_runnable_weight_field():
    bpf_text = bpf_text.replace('RUNNABLE_WEIGHT_FIELD', 'unsigned long runnable_weight;')
else:
    bpf_text = bpf_text.replace('RUNNABLE_WEIGHT_FIELD', '')

# code substitutions
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF & perf_events
b = BPF(text=bpf_text)
# TODO: check for HW counters first and use if more accurate
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.TASK_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)

if args.csv:
    if args.timestamp:
        print("TIME", end=",")
    print("TIMESTAMP_ns", end=",")
    print(",".join("CPU" + str(c) for c in range(ncpu)), end="")
    if args.fullcsv:
        print(",", end="")
        print(",".join("OFFSET_ns_CPU" + str(c) for c in range(ncpu)), end="")
    print()
else:
    print(("Sampling run queues... Output every %s seconds. " +
          "Hit Ctrl-C to end.") % args.interval)

samples = {}
group = {}
last = 0

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    samples[event.ts] = {}
    samples[event.ts]['cpu'] = event.cpu
    samples[event.ts]['len'] = event.len

exiting = 0 if args.interval else 1
slept = float(0)

trigger = int(0.8 * (1000000000 / frequency))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        if not exiting:
            sleep(wakeup_s)
    except KeyboardInterrupt:
        exiting = 1
    b.perf_buffer_poll()
    slept += wakeup_s

    if slept < 0.999 * interval:   # floating point workaround
        continue
    slept = 0

    positive = 0  # number of samples where an idle CPU could have run work
    running = 0
    idle = 0
    if debug >= 2:
        print("DEBUG: begin samples loop, count %d" % len(samples))
    for e in sorted(samples):
        if debug >= 2:
            print("DEBUG: ts %d cpu %d len %d delta %d trig %d" % (e,
                  samples[e]['cpu'], samples[e]['len'], e - last,
                  e - last > trigger))

        # look for time jumps to identify a new sample group
        if e - last > trigger:

            # first first group timestamp, and sanity test
            g_time = 0
            g_max = 0
            for ge in sorted(group):
                if g_time == 0:
                    g_time = ge
                g_max = ge

            # process previous sample group
            if args.csv:
                lens = [0] * ncpu
                offs = [0] * ncpu
                for ge in sorted(group):
                    lens[samples[ge]['cpu']] = samples[ge]['len']
                    if args.fullcsv:
                        offs[samples[ge]['cpu']] = ge - g_time
                if g_time > 0:      # else first sample
                    if args.timestamp:
                        print("%-8s" % strftime("%H:%M:%S"), end=",")
                    print("%d" % g_time, end=",")
                    print(",".join(str(lens[c]) for c in range(ncpu)), end="")
                    if args.fullcsv:
                        print(",", end="")
                        print(",".join(str(offs[c]) for c in range(ncpu)))
                    else:
                        print()
            else:
                # calculate stats
                g_running = 0
                g_queued = 0
                for ge in group:
                    if samples[ge]['len'] > 0:
                        g_running += 1
                    if samples[ge]['len'] > 1:
                        g_queued += samples[ge]['len'] - 1
                g_idle = ncpu - g_running

                # calculate the number of threads that could have run as the
                # minimum of idle and queued
                if g_idle > 0 and g_queued > 0:
                    if g_queued > g_idle:
                        i = g_idle
                    else:
                        i = g_queued
                    positive += i
                running += g_running
                idle += g_idle

            # now sanity test, after -J output
            g_range = g_max - g_time
            if g_range > trigger / 2:
                print(("ERROR: CPU samples arrived at skewed offsets " +
                      "(CPUs may have powered down when idle), " +
                      "spanning %d ns (expected < %d ns). Debug with -J, " +
                      "and see the man page. As output may begin to be " +
                      "unreliable, exiting.") % (g_range, trigger / 2))
                exit()

            # these are done, remove
            for ge in sorted(group):
                del samples[ge]

            # begin next group
            group = {}
            last = e

        # stash this timestamp in a sample group dict
        group[e] = 1

    if not args.csv:
        total = running + idle
        unclaimed = util = 0

        if debug:
            print("DEBUG: hit %d running %d idle %d total %d buffered %d" % (
                  positive, running, idle, total, len(samples)))

        if args.timestamp:
            print("%-8s " % strftime("%H:%M:%S"), end="")

        # output
        if total:
            unclaimed = float(positive) / total
            util = float(running) / total
        print("%%CPU %6.2f%%, unclaimed idle %0.2f%%" % (100 * util,
              100 * unclaimed))

    countdown -= 1
    if exiting or countdown == 0:
        exit()
