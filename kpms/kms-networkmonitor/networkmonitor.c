/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("2.0.5");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Sendto monitor - IP only");

#define AF_INET 2
#define ntohs(x) __builtin_bswap16(x)

struct in_addr { __u32 s_addr; };

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

static int monitor_running = 0;

static void before_sendto(hook_fargs6_t *fargs, void *udata) {
    if (!monitor_running) return;

    struct sockaddr_in __user *usa = (struct sockaddr_in __user *)syscall_argn(fargs, 4);
    if (!usa) return;

    struct sockaddr_in sin;
    if (compat_strncpy_from_user((char *)&sin, (const char __user *)usa, sizeof(sin)) != sizeof(sin))
        return;

    // 过滤：只保留 IPv4 网络通信，忽略本地通信
    if (sin.sin_family != AF_INET) return;

    unsigned char *ip = (unsigned char *)&sin.sin_addr.s_addr;
    printk(KERN_INFO "KMS_NET| %d.%d.%d.%d:%d\n",
           ip[0], ip[1], ip[2], ip[3], ntohs(sin.sin_port));
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