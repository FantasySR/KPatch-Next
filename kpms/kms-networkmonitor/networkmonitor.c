/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Kernel network monitor");

/* ---- 自补充类型 ---- */
#define AF_INET  2
#define AF_INET6 10

struct in_addr { __u32 s_addr; };
struct sock {
    unsigned short  sk_family;
    unsigned short  sk_num;
    __u32           sk_daddr;
    __u32           sk_rcv_saddr;
    unsigned short  sk_dport;
};
struct msghdr {
    void *msg_name; int msg_namelen;
    struct iovec *msg_iov; size_t msg_iovlen;
    void *msg_control; size_t msg_controllen;
    unsigned msg_flags;
};
struct iovec { void __user *iov_base; size_t iov_len; };

#define ntohs(x) (x)

/* 用最原始的方式拼 IP 字符串 */
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

typedef int (*sendmsg_t)(struct sock *, struct msghdr *, size_t);
static sendmsg_t orig_tcp_sendmsg = NULL;
static sendmsg_t orig_udp_sendmsg = NULL;

static int hook_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size) {
    if (monitor_running && sk) {
        char src[16], dst[16];
        ip_to_str(sk->sk_rcv_saddr, src);
        ip_to_str(sk->sk_daddr, dst);
        printk(KERN_INFO "KMS_NET| TCP | %s:%d -> %s:%d | %zu bytes\n",
               src, sk->sk_num, dst, ntohs(sk->sk_dport), size);
    }
    if (orig_tcp_sendmsg) return orig_tcp_sendmsg(sk, msg, size);
    return 0;
}

static int hook_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size) {
    if (monitor_running && sk) {
        char src[16], dst[16];
        ip_to_str(sk->sk_rcv_saddr, src);
        ip_to_str(sk->sk_daddr, dst);
        printk(KERN_INFO "KMS_NET| UDP | %s:%d -> %s:%d | %zu bytes\n",
               src, sk->sk_num, dst, ntohs(sk->sk_dport), size);
    }
    if (orig_udp_sendmsg) return orig_udp_sendmsg(sk, msg, size);
    return 0;
}

static long netmon_control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) { if (out_msg) strncpy(out_msg, "no cmd", outlen); return 0; }
    if (strcmp(args, "run") == 0) { monitor_running=1; printk(KERN_INFO "KMS_NET: running\n"); if (out_msg) strncpy(out_msg, "running", outlen); }
    else if (strcmp(args, "stop") == 0) { monitor_running=0; printk(KERN_INFO "KMS_NET: stopped\n"); if (out_msg) strncpy(out_msg, "stopped", outlen); }
    else { if (out_msg) strncpy(out_msg, "unknown", outlen); }
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved) {
    unsigned long tcp = kallsyms_lookup_name("tcp_sendmsg");
    unsigned long udp = kallsyms_lookup_name("udp_sendmsg");
    if (!tcp || !udp) { printk(KERN_ERR "KMS_NET: symbols missing\n"); return -1; }
    orig_tcp_sendmsg = (sendmsg_t)tcp;
    orig_udp_sendmsg = (sendmsg_t)udp;
    printk(KERN_INFO "KMS_NET: ready (tcp=%lx, udp=%lx)\n", tcp, udp);
    return 0;
}

static long netmon_exit(void *__user reserved) { printk(KERN_INFO "KMS_NET: unloaded\n"); return 0; }

KPM_INIT(init);
KPM_EXIT(netmon_exit);
KPM_CTL0(netmon_control0);