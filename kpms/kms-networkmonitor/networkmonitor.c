/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("1.0.9");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Single hook test with openat");

static void before_openat(hook_fargs4_t *fargs, void *udata) {
    printk(KERN_INFO "KMS_NET| OPENAT called\n");
}

static long init(const char *args, const char *event, void *__user reserved) {
    printk(KERN_INFO "KMS_NET: init start\n");
    hook_err_t err = fp_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    printk(KERN_INFO "KMS_NET: openat hook err=%d\n", err);
    printk(KERN_INFO "KMS_NET: init done\n");
    return 0; // 即使 hook 失败也返回成功，确保模块加载
}

static long netmon_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_openat, before_openat, 0);
    printk(KERN_INFO "KMS_NET: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(netmon_exit);