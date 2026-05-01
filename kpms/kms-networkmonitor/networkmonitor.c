/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Network monitor via syscall hooks");

/* ---- 自补充类型 ---- */
#define AF_INET  2
struct in_addr { __u32 s_addr; };

/* 将 IP 地址转为字符串 */
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

/* ---- Hook: connect (fd, sockaddr, addrlen) ---- */
static void before_connect(hook_fargs3_t *fargs, void *udata) {
    if (!monitor_running) return;
    int fd = (int)syscall_argn(fargs, 0);
    struct sockaddr __user *usa = (struct sockaddr __user *)syscall_argn(fargs, 1);
    if (!usa) return;

    struct sockaddr sa;
    if (compat_strncpy_from_user((char *)&sa, (const char __user *)usa, sizeof(sa)) != sizeof(sa))
        return;
    if (sa.sa_family != AF_INET) return;

    struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
    char ip[16];
    ip_to_str(sin->sin_addr.s_addr, ip);
    printk(KERN_INFO "KMS_NET| CONNECT | fd=%d -> %s:%d | pid=%d\n",
           fd, ip, ntohs(sin->sin_port), current->pid);
}

/* ---- Hook: sendto (fd, buf, len, flags, addr, addrlen) ---- */
static void before_sendto(hook_fargs6_t *fargs, void *udata) {
    if (!monitor_running) return;
    int fd = (int)syscall_argn(fargs, 0);
    size_t len = (size_t)syscall_argn(fargs, 2);
    struct sockaddr __user *usa = (struct sockaddr __user *)syscall_argn(fargs, 4);
    if (!usa) return;

    struct sockaddr sa;
    if (compat_strncpy_from_user((char *)&sa, (const char __user *)usa, sizeof(sa)) != sizeof(sa))
        return;
    if (sa.sa_family != AF_INET) return;

    struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
    char ip[16];
    ip_to_str(sin->sin_addr.s_addr, ip);
    printk(KERN_INFO "KMS_NET| SENDTO | fd=%d -> %s:%d size=%zu | pid=%d\n",
           fd, ip, ntohs(sin->sin_port), len, current->pid);
}

/* ---- Hook: sendmsg (fd, msg, flags) ---- */
static void before_sendmsg(hook_fargs3_t *fargs, void *udata) {
    if (!monitor_running) return;
    int fd = (int)syscall_argn(fargs, 0);
    struct msghdr __user *umsg = (struct msghdr __user *)syscall_argn(fargs, 1);
    if (!umsg) return;

    struct msghdr msg;
    if (compat_strncpy_from_user((char *)&msg, (const char __user *)umsg, sizeof(msg)) != sizeof(msg))
        return;
    if (!msg.msg_name) return;

    struct sockaddr sa;
    if (compat_strncpy_from_user((char *)&sa, (const char __user *)msg.msg_name, sizeof(sa)) != sizeof(sa))
        return;
    if (sa.sa_family != AF_INET) return;

    struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
    char ip[16];
    ip_to_str(sin->sin_addr.s_addr, ip);
    printk(KERN_INFO "KMS_NET| SENDMSG | fd=%d -> %s:%d size=%zu | pid=%d\n",
           fd, ip, ntohs(sin->sin_port), msg.msg_iovlen, current->pid);
}

/* ---- CTL0 控制 ---- */
static long netmon_control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) { if (out_msg) strncpy(out_msg, "no cmd", outlen); return 0; }
    if (strcmp(args, "run") == 0) { monitor_running=1; printk(KERN_INFO "KMS_NET: running\n"); if (out_msg) strncpy(out_msg, "running", outlen); }
    else if (strcmp(args, "stop") == 0) { monitor_running=0; printk(KERN_INFO "KMS_NET: stopped\n"); if (out_msg) strncpy(out_msg, "stopped", outlen); }
    else { if (out_msg) strncpy(out_msg, "unknown", outlen); }
    return 0;
}

/* ---- 生命周期 ---- */
static long init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    err = fp_hook_syscalln(__NR_connect, 3, before_connect, 0, 0);
    if (err) printk(KERN_ERR "KMS_NET: hook connect fail %d\n", err);
    err = fp_hook_syscalln(__NR_sendto, 6, before_sendto, 0, 0);
    if (err) printk(KERN_ERR "KMS_NET: hook sendto fail %d\n", err);
    err = fp_hook_syscalln(__NR_sendmsg, 3, before_sendmsg, 0, 0);
    if (err) printk(KERN_ERR "KMS_NET: hook sendmsg fail %d\n", err);
    printk(KERN_INFO "KMS_NET: hooks installed\n");
    return 0;
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
KPM_CTL0(netmon_control0);