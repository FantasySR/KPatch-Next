/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("1.0.7");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Network syscall hooks with debug");

static int monitor_running = 0;

static void before_connect(hook_fargs3_t *fargs, void *udata) {
    // 先无条件打印，确认回调被触发
    printk(KERN_INFO "KMS_NET| CONNECT triggered\n");
    if (!monitor_running) return;
    printk(KERN_INFO "KMS_NET| CONNECT running\n");
}

static void before_sendto(hook_fargs6_t *fargs, void *udata) {
    printk(KERN_INFO "KMS_NET| SENDTO triggered\n");
    if (!monitor_running) return;
    printk(KERN_INFO "KMS_NET| SENDTO running\n");
}

static void before_sendmsg(hook_fargs3_t *fargs, void *udata) {
    printk(KERN_INFO "KMS_NET| SENDMSG triggered\n");
    if (!monitor_running) return;
    printk(KERN_INFO "KMS_NET| SENDMSG running\n");
}

static long control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) { if (out_msg) strncpy(out_msg, "no cmd", outlen); return 0; }
    if (strcmp(args, "run") == 0) { monitor_running=1; printk(KERN_INFO "KMS_NET: running\n"); if (out_msg) strncpy(out_msg, "running", outlen); }
    else if (strcmp(args, "stop") == 0) { monitor_running=0; printk(KERN_INFO "KMS_NET: stopped\n"); if (out_msg) strncpy(out_msg, "stopped", outlen); }
    else { if (out_msg) strncpy(out_msg, "unknown", outlen); }
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    err = fp_hook_syscalln(__NR_connect, 3, before_connect, 0, 0);
    printk(KERN_INFO "KMS_NET: connect hook err=%d\n", err);
    err = fp_hook_syscalln(__NR_sendto, 6, before_sendto, 0, 0);
    printk(KERN_INFO "KMS_NET: sendto hook err=%d\n", err);
    err = fp_hook_syscalln(__NR_sendmsg, 3, before_sendmsg, 0, 0);
    printk(KERN_INFO "KMS_NET: sendmsg hook err=%d\n", err);
    printk(KERN_INFO "KMS_NET: hooks installed (errors above may be non-fatal)\n");
    return 0;  // 即使 hook 失败也返回成功，确保模块加载
}

static long netmon_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_connect, before_connect, 0);
    fp_unhook_syscalln(__NR_sendto, before_sendto, 0);
    fp_unhook_syscalln(__NR_sendmsg, before_sendmsg, 0);
    printk(KERN_INFO "KMS_NET: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(netmon_exit);
KPM_CTL0(control0);