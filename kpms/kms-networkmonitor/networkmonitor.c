/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("1.0.8");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Test with openat hook");

static int monitor_running = 0;

// 用 openat 验证框架
static void before_openat(hook_fargs4_t *fargs, void *udata) {
    if (!monitor_running) return;
    printk(KERN_INFO "KMS_NET| OPENAT called\n");
}

static long control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) { if (out_msg) strncpy(out_msg, "no cmd", outlen); return 0; }
    if (strcmp(args, "run") == 0) { monitor_running=1; printk(KERN_INFO "KMS_NET: running\n"); if (out_msg) strncpy(out_msg, "running", outlen); }
    else if (strcmp(args, "stop") == 0) { monitor_running=0; printk(KERN_INFO "KMS_NET: stopped\n"); if (out_msg) strncpy(out_msg, "stopped", outlen); }
    else { if (out_msg) strncpy(out_msg, "unknown", outlen); }
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved) {
    printk(KERN_INFO "KMS_NET: init start\n");
    hook_err_t err;
    err = fp_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    printk(KERN_INFO "KMS_NET: openat hook err=%d\n", err);
    if (err) {
        printk(KERN_ERR "KMS_NET: openat hook fail, but module still loads\n");
    }
    printk(KERN_INFO "KMS_NET: init done\n");
    return 0;
}

static long netmon_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_openat, before_openat, 0);
    printk(KERN_INFO "KMS_NET: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(netmon_exit);
KPM_CTL0(control0);