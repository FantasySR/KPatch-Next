/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - 终极智能拦截器（学习+监控模式）
 * 功能：
 * - Hook pread64, pwrite64, process_vm_readv, process_vm_writev
 * - 学习模式：记录调用特征，不输出日志
 * - 监控模式：只输出哈希表中不存在的未知调用
 * - CTL0 命令：clear, start, stop, pid=XXX, off
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
KPM_VERSION("6.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Smart interceptor with learning/monitoring mode");

/* ---------- 哈希表定义 ---------- */
#define HASH_SIZE 1024                     // 哈希表大小（可根据内存调整）
static u64 call_table[HASH_SIZE] = {0};    // 签名表，0 表示空槽
static int call_count = 0;                 // 当前已用槽数
static int learn_mode = 1;                 // 1=学习模式（记录），0=监控模式（输出未知）
static int target_pid = 0;                 // process_vm 的 PID 过滤

/* ---------- 简易哈希函数（FNV-1a 变体） ---------- */
static u64 hash_signature(int fd, loff_t pos, size_t count, const unsigned char *data, int data_len)
{
    u64 hash = 14695981039346656037ULL; // FNV offset basis
    // 混合 fd
    hash ^= (u64)fd;
    hash *= 1099511628211ULL;
    // 混合 pos
    hash ^= (u64)pos;
    hash *= 1099511628211ULL;
    // 混合 count
    hash ^= (u64)count;
    hash *= 1099511628211ULL;
    // 混合数据前 32 字节
    for (int i = 0; i < data_len; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

/* ---------- 哈希表操作 ---------- */
static int is_signature_present(u64 sig)
{
    int idx = sig % HASH_SIZE;
    int tried = 0;
    while (call_table[idx] != 0 && tried < HASH_SIZE) {
        if (call_table[idx] == sig)
            return 1; // 找到
        idx = (idx + 1) % HASH_SIZE;
        tried++;
    }
    return 0;
}

static void insert_signature(u64 sig)
{
    if (call_count >= HASH_SIZE)
        return; // 表满，无法插入
    int idx = sig % HASH_SIZE;
    while (call_table[idx] != 0) {
        if (call_table[idx] == sig)
            return; // 已存在，不重复插入
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

/* ---------- 辅助：从用户空间安全读取前 32 字节数据 ---------- */
static void read_data_sample(const void __user *buf, size_t count, unsigned char *out, int *out_len)
{
    if (!buf || count == 0) {
        *out_len = 0;
        return;
    }
    int len = count < 32 ? count : 32;
    if (compat_strncpy_from_user((char *)out, (const char __user *)buf, len) > 0) {
        *out_len = len;
    } else {
        *out_len = 0;
    }
}

/* ---------- CTL0 控制命令 ---------- */
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
        printk(KERN_INFO "KMS: monitoring mode (output unknown)\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "monitoring", outlen);
    } else if (strcmp(args, "stop") == 0) {
        learn_mode = 1;
        printk(KERN_INFO "KMS: learning mode (recording)\n");
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
        printk(KERN_INFO "KMS: PID filter set to %d\n", target_pid);
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

/* ---------- prw Hook 回调（学习/监控逻辑） ---------- */
static void before_pread64(hook_fargs4_t *fargs, void *udata)
{
    int fd = (int)syscall_argn(fargs, 0);
    void __user *buf = (void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    unsigned char sample[32];
    int sample_len = 0;
    read_data_sample(buf, count, sample, &sample_len);
    u64 sig = hash_signature(fd, pos, count, sample, sample_len);

    if (learn_mode) {
        // 学习模式：只记录，不输出
        insert_signature(sig);
    } else {
        // 监控模式：仅输出表中不存在的调用
        if (!is_signature_present(sig)) {
            printk(KERN_INFO "KMS| pread64 | FD=%d POS=%lld SIZE=%zu\n", fd, pos, count);
        }
    }
}

static void before_pwrite64(hook_fargs4_t *fargs, void *udata)
{
    int fd = (int)syscall_argn(fargs, 0);
    const void __user *buf = (const void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    unsigned char sample[32];
    int sample_len = 0;
    read_data_sample(buf, count, sample, &sample_len);
    u64 sig = hash_signature(fd, pos, count, sample, sample_len);

    if (learn_mode) {
        insert_signature(sig);
    } else {
        if (!is_signature_present(sig)) {
            printk(KERN_INFO "KMS| pwrite64 | FD=%d POS=%lld SIZE=%zu\n", fd, pos, count);
        }
    }
}

/* ---------- process_vm Hook（保留 PID 过滤） ---------- */
static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid > 0 && tpid != target_pid)
        return;
    printk(KERN_INFO "KMS| process_vm_readv | TARGET=%d\n", tpid);
}

static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid > 0 && tpid != target_pid)
        return;
    printk(KERN_INFO "KMS| process_vm_writev | TARGET=%d\n", tpid);
}

/* ---------- 模块初始化 ---------- */
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

    printk(KERN_INFO "KMS: loaded (learning mode)\n");
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