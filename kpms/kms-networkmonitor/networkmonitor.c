/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("2.0.6");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Debug sendto parameters");

static int monitor_running = 0;

static void before_sendto(hook_fargs6_t *fargs, void *udata) {
    if (!monitor_running) return;

    // 打印 sendto 的六个参数（全部作为 unsigned long）
    unsigned long arg0 = syscall_argn(fargs, 0);
    unsigned long arg1 = syscall_argn(fargs, 1);
    unsigned long arg2 = syscall_argn(fargs, 2);
    unsigned long arg3 = syscall_argn(fargs, 3);
    unsigned long arg4 = syscall_argn(fargs, 4);
    unsigned long arg5 = syscall_argn(fargs, 5);

    printk(KERN_INFO "KMS_NET| sendto args: %lx %lx %lx %lx %lx %lx\n",
           arg0, arg1, arg2, arg3, arg4, arg5);
}

static long control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) { if (out_msg) strncpy(out_msg, "no cmd", outlen); return 0; }
    if (strcmp(args, "run") == 0) { monitor_running=1; printk(KERN_INFO "KMS_NET: running\n"); if (out_msg) strncpy(out_msg, "running", outlen); }
    else if (strcmp(args, "stop") == 0) { monitor_running=0; printk(KERN_INFO "KMS_NET: stopped\n"); if (out_msg) strncpy(out_msg, "stopped", outlen); }
    else { if (out_msg) strncpy(out_msg, "unknown", outlen); }
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err = fp_hook_syscalln(__NR_sendto, 6, before_sendto, 0, 0);
    printk(KERN_INFO "KMS_NET: sendto hook err=%d\n", err);
    return 0;
}

static long netmon_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_sendto, before_sendto, 0);
    printk(KERN_INFO "KMS_NET: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(netmon_exit);
KPM_CTL0(control0);