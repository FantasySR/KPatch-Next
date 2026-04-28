/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - 集成版拦截器（修正头文件）
 * 功能:
 * - Hook pread64, pwrite64, process_vm_readv, process_vm_writev
 * - PID 过滤（process_vm 按目标 PID，pread64/pwrite64 全量输出）
 * - 日志同时写入环形缓冲区和 dmesg
 * - CTL0 命令: run, stop, pid=XXX, read, off
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <stdarg.h>   // <-- 添加这个头文件

KPM_NAME("KernelMemorySky");
KPM_VERSION("3.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Integrated interceptor with ring buffer + CTL0");

/* ---------- 环形缓冲区 ---------- */
#define BUF_SIZE (1024 * 64)           // 64KB
static char ring_buf[BUF_SIZE];
static int ring_head = 0, ring_tail = 0, ring_count = 0;

static void ring_write(const char *data, int len) {
    for (int i = 0; i < len; i++) {
        ring_buf[ring_head] = data[i];
        ring_head = (ring_head + 1) % BUF_SIZE;
        if (ring_count < BUF_SIZE) ring_count++;
    }
}

/* 简化版格式化写入 */
static void log_to_ring_and_dmesg(const char *fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        ring_write(buf, len);
        printk(KERN_INFO "KMS| %s", buf);
    }
}

/* ---------- PID 过滤变量 ---------- */
static int target_pid = 0;
static int running = 1;    // run/stop 控制

/* ---------- CTL0 命令处理 ---------- */
static long interceptor_control0(const char *args, char *__user out_msg, int outlen) {
    if (!args) {
        if (out_msg && outlen > 0) strncpy(out_msg, "no cmd", outlen);
        return 0;
    }

    if (strcmp(args, "run") == 0) {
        running = 1;
        log_to_ring_and_dmesg("STATUS: running\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "running", outlen);
    } else if (strcmp(args, "stop") == 0) {
        running = 0;
        log_to_ring_and_dmesg("STATUS: stopped\n");
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
        log_to_ring_and_dmesg("PID filter set to %d\n", target_pid);
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else if (strcmp(args, "off") == 0) {
        target_pid = 0;
        log_to_ring_and_dmesg("PID filter off\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else if (strcmp(args, "read") == 0) {
        if (!out_msg || outlen <= 0) return 0;
        int avail = ring_count;
        if (avail == 0) {
            strncpy(out_msg, "(empty)", outlen);
            return 0;
        }
        int to_copy = (outlen - 1 < avail) ? (outlen - 1) : avail;
        for (int i = 0; i < to_copy; i++)
            out_msg[i] = ring_buf[(ring_tail + i) % BUF_SIZE];
        out_msg[to_copy] = '\0';
        ring_tail = (ring_tail + to_copy) % BUF_SIZE;
        ring_count -= to_copy;
    } else {
        if (out_msg && outlen > 0) strncpy(out_msg, "unknown", outlen);
    }
    return 0;
}

/* ---------- Hook 回调 ---------- */
static void before_pread64(hook_fargs4_t *fargs, void *udata) {
    if (!running) return;
    int fd = (int)syscall_argn(fargs, 0);
    void __user *buf = (void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);
    log_to_ring_and_dmesg("pread64 FD=%d BUF=%px COUNT=%zu POS=%lld\n", fd, buf, count, pos);
}

static void before_pwrite64(hook_fargs4_t *fargs, void *udata) {
    if (!running) return;
    int fd = (int)syscall_argn(fargs, 0);
    const void __user *buf = (const void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);
    log_to_ring_and_dmesg("pwrite64 FD=%d BUF=%px COUNT=%zu POS=%lld\n", fd, buf, count, pos);
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
    log_to_ring_and_dmesg("process_vm_readv TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
                          tpid, local_iov, liovcnt, remote_iov, riovcnt, flags);
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
    log_to_ring_and_dmesg("process_vm_writev TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
                          tpid, local_iov, liovcnt, remote_iov, riovcnt, flags);
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

    log_to_ring_and_dmesg("Interceptor loaded (ring buffer ready)\n");
    return 0;
}

static long interceptr_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_pread64, before_pread64, 0);
    fp_unhook_syscalln(__NR_pwrite64, before_pwrite64, 0);
    fp_unhook_syscalln(__NR_process_vm_readv, before_process_vm_readv, 0);
    fp_unhook_syscalln(__NR_process_vm_writev, before_process_vm_writev, 0);
    printk(KERN_INFO "KMS: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(interceptr_exit);
KPM_CTL0(interceptor_control0);