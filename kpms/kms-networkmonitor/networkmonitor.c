/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("2.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Http URL catcher - raw dump");

static int monitor_running = 0;

static void before_sendto(hook_fargs6_t *fargs, void *udata) {
    if (!monitor_running) return;

    const char __user *user_buf = (const char __user *)syscall_argn(fargs, 1);
    size_t len = (size_t)syscall_argn(fargs, 2);
    if (!user_buf || len == 0) return;

    // 拷贝最多 512 字节到内核缓冲区，避免数据过大
    char tmp[512];
    int copy_len = len < sizeof(tmp) ? len : sizeof(tmp);
    copy_len = compat_strncpy_from_user(tmp, user_buf, copy_len);
    if (copy_len <= 0) return;

    // 只关注 HTTP 请求（以 GET / POST 开头）
    if (copy_len < 4) return;
    if (!(tmp[0] == 'G' && tmp[1] == 'E' && tmp[2] == 'T' && tmp[3] == ' ') &&
        !(tmp[0] == 'P' && tmp[1] == 'O' && tmp[2] == 'S' && tmp[3] == 'T'))
        return;

    // 打印整个请求头，你就能看到 URL 和 Host
    printk(KERN_INFO "KMS_NET| HTTP: %.*s\n", copy_len, tmp);
}

static long control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) { if (out_msg) strncpy(out_msg, "no cmd", outlen); return 0; }
    if (strcmp(args, "run") == 0) { monitor_running = 1; printk(KERN_INFO "KMS_NET: running\n"); }
    else if (strcmp(args, "stop") == 0) { monitor_running = 0; printk(KERN_INFO "KMS_NET: stopped\n"); }
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