/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - 终极拦截器 (Netlink 版本)
 * 功能:
 * - Hook pread64, pwrite64, process_vm_readv, process_vm_writev
 * - PID 过滤（process_vm 按目标 PID，pread64/pwrite64 全量输出）
 * - 通过 Netlink (协议号 30) 发送拦截日志
 * - CTL0 控制: run, stop, pid=XXX, off
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

KPM_NAME("KernelMemorySky");
KPM_VERSION("4.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Final interceptor with Netlink");

/* ---------- Netlink 相关 ---------- */
#define NETLINK_KMS 30
static struct sock *nl_sk = NULL;

/* 发送 Netlink 消息到用户空间 */
static void nl_send_msg(const char *msg, int len) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int total_size = NLMSG_SPACE(len);

    if (!nl_sk || !msg || len == 0) return;

    skb = alloc_skb(total_size, GFP_ATOMIC);
    if (!skb) return;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, total_size - sizeof(*nlh), 0);
    if (!nlh) {
        kfree_skb(skb);
        return;
    }
    memcpy(nlmsg_data(nlh), msg, len);
    nlmsg_end(skb, nlh);

    if (nlmsg_unicast(nl_sk, skb, 0) < 0) {
        kfree_skb(skb);
    }
}

/* ---------- PID 过滤变量 ---------- */
static int target_pid = 0;
static int running = 1;

/* ---------- CTL0 命令处理 ---------- */
static long interceptor_control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) {
        if (out_msg && outlen > 0) strncpy(out_msg, "no cmd", outlen);
        return 0;
    }

    if (strcmp(args, "run") == 0) {
        running = 1;
        printk(KERN_INFO "KMS: run\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "running", outlen);
    } else if (strcmp(args, "stop") == 0) {
        running = 0;
        printk(KERN_INFO "KMS: stop\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "stopped", outlen);
    } else if (strncmp(args, "pid=", 4) == 0) {
        const char *p = args + 4;
        int pid = 0;
        while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
        if (*p != '\0' || pid <= 0) {
            if (out_msg && outlen > 0) strncpy(out_msg, "err", outlen);
            return -EINVAL;
        }
        target_pid = pid;
        printk(KERN_INFO "KMS: PID filter %d\n", target_pid);
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else if (strcmp(args, "off") == 0) {
        target_pid = 0;
        printk(KERN_INFO "KMS: PID filter off\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else {
        if (out_msg && outlen > 0) strncpy(out_msg, "unknown", outlen);
    }
    return 0;
}

/* ---------- Hook 回调 (详细日志通过 Netlink 发送) ---------- */
static void before_pread64(hook_fargs4_t *fargs, void *udata) {
    if (!running) return;
    int fd = (int)syscall_argn(fargs, 0);
    void __user *buf = (void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    char log_buf[256];
    int len = snprintf(log_buf, sizeof(log_buf),
                       "KMS| pread64 | FD=%d BUF=%px COUNT=%zu POS=%lld\n",
                       fd, buf, count, pos);
    if (len > 0) nl_send_msg(log_buf, len);
}

static void before_pwrite64(hook_fargs4_t *fargs, void *udata) {
    if (!running) return;
    int fd = (int)syscall_argn(fargs, 0);
    const void __user *buf = (const void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    char log_buf[256];
    int len = snprintf(log_buf, sizeof(log_buf),
                       "KMS| pwrite64 | FD=%d BUF=%px COUNT=%zu POS=%lld\n",
                       fd, buf, count, pos);
    if (len > 0) nl_send_msg(log_buf, len);
}

static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata) {
    if (!running) return;
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid > 0 && tpid != target_pid) return;
    void __user *local_iov = (void __user *)syscall_argn(fargs, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(fargs, 2);
    void __user *remote_iov = (void __user *)syscall_argn(fargs, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(fargs, 4);
    unsigned long flags = (unsigned long)syscall_argn(fargs, 5);

    char log_buf[256];
    int len = snprintf(log_buf, sizeof(log_buf),
                       "KMS| process_vm_readv | TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
                       tpid, local_iov, liovcnt, remote_iov, riovcnt, flags);
    if (len > 0) nl_send_msg(log_buf, len);
}

static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata) {
    if (!running) return;
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid > 0 && tpid != target_pid) return;
    void __user *local_iov = (void __user *)syscall_argn(fargs, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(fargs, 2);
    void __user *remote_iov = (void __user *)syscall_argn(fargs, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(fargs, 4);
    unsigned long flags = (unsigned long)syscall_argn(fargs, 5);

    char log_buf[256];
    int len = snprintf(log_buf, sizeof(log_buf),
                       "KMS| process_vm_writev | TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
                       tpid, local_iov, liovcnt, remote_iov, riovcnt, flags);
    if (len > 0) nl_send_msg(log_buf, len);
}

/* ---------- 模块初始化 ---------- */
static long init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    err = fp_hook_syscalln(__NR_pread64, 4, before_pread64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pread64 fail %d\n", err);
    err = fp_hook_syscalln(__NR_pwrite64, 4, before_pwrite64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pwrite64 fail %d\n", err);
    err = fp_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_readv fail %d\n", err);
    err = fp_hook_syscalln(__NR_process_vm_writev, 6, before_process_vm_writev, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_writev fail %d\n", err);

    /* 初始化 Netlink socket */
    struct netlink_kernel_cfg cfg = {
        .input = NULL,   // 我们不接收用户态发来的消息
    };
    nl_sk = netlink_kernel_create(&init_net, NETLINK_KMS, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "KMS: netlink create failed\n");
        return -1;
    }
    printk(KERN_INFO "KMS: Netlink loaded (protocol %d)\n", NETLINK_KMS);
    return 0;
}

static long interceptr_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_pread64, before_pread64, 0);
    fp_unhook_syscalln(__NR_pwrite64, before_pwrite64, 0);
    fp_unhook_syscalln(__NR_process_vm_readv, before_process_vm_readv, 0);
    fp_unhook_syscalln(__NR_process_vm_writev, before_process_vm_writev, 0);
    if (nl_sk) netlink_kernel_release(nl_sk);
    printk(KERN_INFO "KMS: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(interceptr_exit);
KPM_CTL0(interceptor_control0);