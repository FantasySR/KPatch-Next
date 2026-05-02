/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("2.0.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Single connect hook test");

static void before_connect(hook_fargs3_t *fargs, void *udata) {
    printk(KERN_INFO "KMS_NET| CONNECT called\n");
}

static long init(const char *args, const char *event, void *__user reserved) {
    printk(KERN_INFO "KMS_NET: init start\n");
    hook_err_t err = fp_hook_syscalln(__NR_connect, 3, before_connect, 0, 0);
    printk(KERN_INFO "KMS_NET: connect hook err=%d\n", err);
    printk(KERN_INFO "KMS_NET: init done\n");
    return 0;
}

static long netmon_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_connect, before_connect, 0);
    printk(KERN_INFO "KMS_NET: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(netmon_exit);