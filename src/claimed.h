#ifndef __CLAIMED_H__
#define __CLAIMED_H__

#define IS_KPROBE_RQ_CLOCK 1

struct data_t {
    unsigned int ts;
    unsigned int cpu;
    unsigned int len;
};

#endif // __CLAIMED_H__