/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - 增强拦截器 (地址可见版)
 * - pread64/pwrite64: 监控模式下输出十六进制 POS, BUF, DATA
 * - process_vm_*: 仅当目标 PID 设置时输出
 * - 命令: clear, start, stop, pid=XXX, off, fdmax=N
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("KernelMemorySky");
KPM_VERSION("6.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Enhanced interceptor with hex POS and data dump");

#define HASH_SIZE 1024
static u64 call_table[HASH_SIZE] = {0};
static int call_count = 0;
static int learn_mode = 1;         // 1=学习, 0=监控
static int target_pid = 0;
static int fd_max = 0;             // 0 表示不过滤

/* ---- 哈希函数 ---- */
static u64 hash_signature(int fd, loff_t pos, size_t count, const unsigned char *data, int data_len)
{
    u64 hash = 14695981039346656037ULL;
    hash ^= (u64)fd;        hash *= 1099511628211ULL;
    hash ^= (u64)pos;       hash *= 1099511628211ULL;
    hash ^= (u64)count;     hash *= 1099511628211ULL;
    for (int i = 0; i < data_len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int is_signature_present(u64 sig)
{
    int idx = sig % HASH_SIZE;
    int tried = 0;
    while (call_table[idx] != 0 && tried < HASH_SIZE) {
        if (call_table[idx] == sig) return 1;
        idx = (idx + 1) % HASH_SIZE;
        tried++;
    }
    return 0;
}

static void insert_signature(u64 sig)
{
    if (call_count >= HASH_SIZE) return;
    int idx = sig % HASH_SIZE;
    while (call_table[idx] != 0) {
        if (call_table[idx] == sig) return;
        idx = (idx + 1) % HASH_SIZE;
    }
    call_table[idx] = sig;
    call_count++;
}

static void clear_table(void)
{
    memset(call_table, 0, sizeof(call_table));
    call_count = 0;
    printk(KERN_INFO "KMS: hash table cleared\n");
}

/* ---- 安全读取数据样本（最多 8 字节） ---- */
static void read_data_sample(const void __user *buf, size_t count, unsigned char *out, int *out_len)
{
    if (!buf || count == 0) {
        *out_len = 0;
        return;
    }
    int len = count < 8 ? count : 8;
    if (compat_strncpy_from_user((char *)out, (const char __user *)buf, len) > 0) {
        *out_len = len;
    } else {
        *out_len = 0;
    }
}

/* ---- 打印十六进制数据区块 ---- */
static void print_hex(const unsigned char *data, int len)
{
    for (int i = 0; i < len; i++) {
        printk(KERN_INFO " %02x", data[i]);
    }
}

/* ---- CTL0 控制命令 ---- */
static long interceptor_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args) {
        if (out_msg && outlen > 0) strncpy(out_msg, "no cmd", outlen);
        return 0;
    }

    if (strcmp(args, "clear") == 0) {
        clear_table();
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else if (strcmp(args, "start") == 0) {
        learn_mode = 0;
        printk(KERN_INFO "KMS: monitoring mode\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "monitoring", outlen);
    } else if (strcmp(args, "stop") == 0) {
        learn_mode = 1;
        printk(KERN_INFO "KMS: learning mode\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "learning", outlen);
    } else if (strncmp(args, "pid=", 4) == 0) {
        const char *p = args + 4;
        int pid = 0;
        while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
        if (*p != '\0' || pid <= 0) {
            if (out_msg && outlen > 0) strncpy(out_msg, "err", outlen);
            return -EINVAL;
        }
        target_pid = pid;
        printk(KERN_INFO "KMS: target PID = %d\n", target_pid);
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else if (strncmp(args, "fdmax=", 6) == 0) {
        const char *p = args + 6;
        int val = 0;
        while (*p >= '0' && *p <= '9') val = val * 10 + (*p++ - '0');
        if (*p != '\0' || val < 0) {
            if (out_msg && outlen > 0) strncpy(out_msg, "err", outlen);
            return -EINVAL;
        }
        fd_max = val;
        printk(KERN_INFO "KMS: fd_max set to %d\n", fd_max);
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else if (strcmp(args, "off") == 0) {
        target_pid = 0;
        fd_max = 0;
        printk(KERN_INFO "KMS: PID and FD filters off\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else {
        if (out_msg && outlen > 0) strncpy(out_msg, "unknown", outlen);
    }
    return 0;
}

/* ---- prw Hook（增强输出） ---- */
static void before_pread64(hook_fargs4_t *fargs, void *udata)
{
    int fd = (int)syscall_argn(fargs, 0);
    void __user *buf = (void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    // fd 阈值过滤（0 表示不过滤）
    if (fd_max > 0 && fd > fd_max) return;

    unsigned char sample[8];
    int sample_len = 0;
    read_data_sample(buf, count, sample, &sample_len);
    u64 sig = hash_signature(fd, pos, count, sample, sample_len);

    if (learn_mode) {
        insert_signature(sig);
    } else {
        if (!is_signature_present(sig)) {
            if (sample_len > 0) {
                printk(KERN_INFO "KMS| pread64 | FD=%d POS=0x%llx SIZE=%zu BUF=%px DATA=",
                       fd, pos, count, buf);
                print_hex(sample, sample_len);
                printk(KERN_INFO "\n");
            } else {
                printk(KERN_INFO "KMS| pread64 | FD=%d POS=0x%llx SIZE=%zu BUF=%px\n",
                       fd, pos, count, buf);
            }
        }
    }
}

static void before_pwrite64(hook_fargs4_t *fargs, void *udata)
{
    int fd = (int)syscall_argn(fargs, 0);
    const void __user *buf = (const void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    if (fd_max > 0 && fd > fd_max) return;

    unsigned char sample[8];
    int sample_len = 0;
    read_data_sample(buf, count, sample, &sample_len);
    u64 sig = hash_signature(fd, pos, count, sample, sample_len);

    if (learn_mode) {
        insert_signature(sig);
    } else {
        if (!is_signature_present(sig)) {
            if (sample_len > 0) {
                printk(KERN_INFO "KMS| pwrite64 | FD=%d POS=0x%llx SIZE=%zu BUF=%px DATA=",
                       fd, pos, count, buf);
                print_hex(sample, sample_len);
                printk(KERN_INFO "\n");
            } else {
                printk(KERN_INFO "KMS| pwrite64 | FD=%d POS=0x%llx SIZE=%zu BUF=%px\n",
                       fd, pos, count, buf);
            }
        }
    }
}

/* ---- vm Hook（强制 PID 过滤） ---- */
static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid <= 0 || tpid != target_pid) return;
    printk(KERN_INFO "KMS| process_vm_readv | TARGET=%d\n", tpid);
}

static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid <= 0 || tpid != target_pid) return;
    printk(KERN_INFO "KMS| process_vm_writev | TARGET=%d\n", tpid);
}

/* ---- 模块生命周期 ---- */
static long init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;
    err = fp_hook_syscalln(__NR_pread64, 4, before_pread64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pread64 fail %d\n", err);
    err = fp_hook_syscalln(__NR_pwrite64, 4, before_pwrite64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pwrite64 fail %d\n", err);
    err = fp_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_readv fail %d\n", err);
    err = fp_hook_syscalln(__NR_process_vm_writev, 6, before_process_vm_writev, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_writev fail %d\n", err);

    printk(KERN_INFO "KMS: loaded (v6.2.0, learning mode)\n");
    return 0;
}

static long interceptr_exit(void *__user reserved)
{
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