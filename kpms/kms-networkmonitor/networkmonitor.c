/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("2.0.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Network monitor - connect hook only");

/* 补充网络结构体 */
#define AF_INET 2
#define ntohs(x) __builtin_bswap16(x)

struct in_addr {
    __u32 s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

static void ip_to_str(__u32 addr, char *out) {
    unsigned char *p = (unsigned char *)&addr;
    int pos = 0;
    for (int i = 0; i < 4; i++) {
        if (i > 0) out[pos++] = '.';
        unsigned char byte = p[i];
        if (byte >= 100) { out[pos++] = '0' + byte/100; byte %= 100; }
        if (byte >= 10 || p[i] >= 100) { out[pos++] = '0' + byte/10; byte %= 10; }
        out[pos++] = '0' + byte;
    }
    out[pos] = '\0';
}

static int monitor_running = 0;

/* ---- 只挂钩 connect ---- */
static void before_connect(hook_fargs3_t *fargs, void *udata) {
    if (!monitor_running) return;

    int fd = (int)syscall_argn(fargs, 0);
    struct sockaddr_in __user *usa = (struct sockaddr_in __user *)syscall_argn(fargs, 1);
    if (!usa) return;

    struct sockaddr_in sin;
    if (compat_strncpy_from_user((char *)&sin, (const char __user *)usa, sizeof(sin)) != sizeof(sin))
        return;
    if (sin.sin_family != AF_INET) return;

    char ip[16];
    ip_to_str(sin.sin_addr.s_addr, ip);
    printk(KERN_INFO "KMS_NET| CONNECT | fd=%d -> %s:%d\n",
           fd, ip, ntohs(sin.sin_port));
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
KPM_CTL0(control0);