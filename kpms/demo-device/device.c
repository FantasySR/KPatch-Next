/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("DeviceTest");
KPM_VERSION("1.1.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Static ring buffer + CTL0 read");

#define BUF_SIZE (1024 * 64)  // 64KB
static char rbuf[BUF_SIZE];
static int rhead = 0, rtail = 0, rcount = 0;

static void ring_write(const char *data, int len) {
    for (int i = 0; i < len; i++) {
        rbuf[rhead] = data[i];
        rhead = (rhead + 1) % BUF_SIZE;
        if (rcount < BUF_SIZE) rcount++;
    }
}

static long ct0_handler(const char *args, char *__user out_msg, int outlen) {
    if (!args) {
        if (out_msg && outlen > 0) strncpy(out_msg, "no cmd", outlen);
        return 0;
    }
    if (strcmp(args, "read") == 0) {
        if (!out_msg || outlen <= 0) return 0;
        int avail = rcount;
        if (avail == 0) {
            strncpy(out_msg, "(empty)", outlen);
            return 0;
        }
        int to_copy = (outlen - 1 < avail) ? (outlen - 1) : avail;
        int i;
        for (i = 0; i < to_copy; i++) {
            out_msg[i] = rbuf[(rtail + i) % BUF_SIZE];
        }
        out_msg[to_copy] = '\0';
        rtail = (rtail + to_copy) % BUF_SIZE;
        rcount -= to_copy;
        return 0;
    }
    if (strcmp(args, "test") == 0) {
        ring_write("Hello from ring buffer!\n", 23);
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
        return 0;
    }
    if (out_msg && outlen > 0) strncpy(out_msg, "unknown", outlen);
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved) {
    printk(KERN_INFO "DeviceTest: static buffer ready\n");
    return 0;
}

static long dev_exit(void *__user reserved) {
    printk(KERN_INFO "DeviceTest: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(dev_exit);
KPM_CTL0(ct0_handler);