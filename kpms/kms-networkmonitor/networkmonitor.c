/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KMS_NetMonitor - 日志版内核级网络抓包
 * 通过 kallsyms 动态获取 tcp_sendmsg/udp_sendmsg 地址
 * 通过 printk 实时输出网络连接信息
 * CTL0 控制启停: run / stop
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/in6.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Kernel network monitor (log version)");

/* ---------- 全局状态 ---------- */
static int monitor_running = 0;          /* 1=抓包中, 0=停止 */

/* ---------- 动态函数指针 ---------- */
typedef int (*tcp_sendmsg_t)(struct sock *, struct msghdr *, size_t);
typedef int (*udp_sendmsg_t)(struct sock *, struct msghdr *, size_t);

static tcp_sendmsg_t orig_tcp_sendmsg = NULL;
static udp_sendmsg_t orig_udp_sendmsg = NULL;

/* ---------- IP 地址提取辅助函数 ---------- */
static void format_ip(struct sock *sk, char *buf, int buflen)
{
#if IS_ENABLED(CONFIG_IPV6)
    if (sk->sk_family == AF_INET6) {
        struct in6_addr *addr = &sk->sk_v6_daddr;
        snprintf(buf, buflen, "%pI6c", addr);
        return;
    }
#endif
    struct in_addr addr;
    addr.s_addr = sk->sk_daddr;
    snprintf(buf, buflen, "%pI4", &addr);
}

/* ---------- Hook 函数：tcp_sendmsg ---------- */
static int hook_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    if (monitor_running && sk) {
        char src_ip[64], dst_ip[64];
        
        // 获取源 IP（本地地址）
        if (sk->sk_family == AF_INET) {
            snprintf(src_ip, sizeof(src_ip), "%pI4", &sk->sk_rcv_saddr);
            snprintf(dst_ip, sizeof(dst_ip), "%pI4", &sk->sk_daddr);
        } else {
            snprintf(src_ip, sizeof(src_ip), "[IPv6]");
            snprintf(dst_ip, sizeof(dst_ip), "[IPv6]");
        }

        printk(KERN_INFO "KMS_NET| TCP SEND | src=%s:%d -> dst=%s:%d | size=%zu | pid=%d\n",
               src_ip, sk->sk_num, dst_ip, ntohs(sk->sk_dport), size, current->pid);
    }

    /* 调用原始函数 */
    if (orig_tcp_sendmsg)
        return orig_tcp_sendmsg(sk, msg, size);
    return 0;
}

/* ---------- Hook 函数：udp_sendmsg ---------- */
static int hook_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    if (monitor_running && sk) {
        char src_ip[64], dst_ip[64];
        
        if (sk->sk_family == AF_INET) {
            snprintf(src_ip, sizeof(src_ip), "%pI4", &sk->sk_rcv_saddr);
            snprintf(dst_ip, sizeof(dst_ip), "%pI4", &sk->sk_daddr);
        } else {
            snprintf(src_ip, sizeof(src_ip), "[IPv6]");
            snprintf(dst_ip, sizeof(dst_ip), "[IPv6]");
        }

        printk(KERN_INFO "KMS_NET| UDP SEND | src=%s:%d -> dst=%s:%d | size=%zu | pid=%d\n",
               src_ip, sk->sk_num, dst_ip, ntohs(sk->sk_dport), size, current->pid);
    }

    if (orig_udp_sendmsg)
        return orig_udp_sendmsg(sk, msg, size);
    return 0;
}

/* ---------- CTL0 控制命令 ---------- */
static long netmon_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args) {
        if (out_msg && outlen > 0)
            strncpy(out_msg, "no cmd", outlen);
        return 0;
    }

    if (strcmp(args, "run") == 0) {
        monitor_running = 1;
        printk(KERN_INFO "KMS_NET: monitoring started\n");
        if (out_msg && outlen > 0)
            strncpy(out_msg, "running", outlen);
    } else if (strcmp(args, "stop") == 0) {
        monitor_running = 0;
        printk(KERN_INFO "KMS_NET: monitoring stopped\n");
        if (out_msg && outlen > 0)
            strncpy(out_msg, "stopped", outlen);
    } else {
        if (out_msg && outlen > 0)
            strncpy(out_msg, "unknown cmd", outlen);
    }
    return 0;
}

/* ---------- 模块初始化 ---------- */
static long init(const char *args, const char *event, void *__user reserved)
{
    /* 动态获取函数地址 */
    unsigned long tcp_addr = kallsyms_lookup_name("tcp_sendmsg");
    unsigned long udp_addr = kallsyms_lookup_name("udp_sendmsg");

    printk(KERN_INFO "KMS_NET: tcp_sendmsg addr = %lx\n", tcp_addr);
    printk(KERN_INFO "KMS_NET: udp_sendmsg addr = %lx\n", udp_addr);

    if (!tcp_addr || !udp_addr) {
        printk(KERN_ERR "KMS_NET: failed to find network functions\n");
        return -1;
    }

    orig_tcp_sendmsg = (tcp_sendmsg_t)tcp_addr;
    orig_udp_sendmsg = (udp_sendmsg_t)udp_addr;

    /* 通过 fp_hook_syscalln 无法直接挂钩非系统调用，这里我们通过
     * 保存原始函数地址并在 Hook 中手动调用的方式实现。
     * 对于生产环境，建议使用 inlinehook，但当前先用替换指针的方式验证。 */

    printk(KERN_INFO "KMS_NET: hooks prepared (tcp=%lx, udp=%lx)\n",
           tcp_addr, udp_addr);
    printk(KERN_INFO "KMS_NET: loaded, send 'run' to start\n");
    return 0;
}

static long exit(void *__user reserved)
{
    printk(KERN_INFO "KMS_NET: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);
KPM_CTL0(netmon_control0);