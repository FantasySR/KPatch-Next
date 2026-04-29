/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - 完整拦截器 v6.4.3 (文件内容清空 + 所有Hook)
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
KPM_VERSION("6.4.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Full interceptor with file truncate on exit");

/* ---------- 补充缺失的宏 ---------- */
#ifndef O_CREAT
#define O_CREAT  0x40
#endif
#ifndef O_WRONLY
#define O_WRONLY 0x1
#endif
#ifndef O_TRUNC
#define O_TRUNC  0x200
#endif

#define IS_ERR(x) ((unsigned long)(void *)(x) >= (unsigned long)(-4095))
typedef void *fl_owner_t;

typedef struct file *(*filp_open_t)(const char *, int, umode_t);
typedef ssize_t (*kernel_write_t)(struct file *, const void *, size_t, loff_t *);
typedef int (*filp_close_t)(struct file *, fl_owner_t);

/* ---------- 哈希表 ---------- */
#define HASH_SIZE 1024
static u64 call_table[HASH_SIZE] = {0};
static int call_count = 0;
static int learn_mode = 1;        /* 1=学习, 0=监控 */
static int output_format = 0;     /* 0=分析模式, 1=原生模式 */
static int target_pid = 0;
static int fd_max = 0;

static filp_open_t filp_open_ptr = NULL;
static kernel_write_t kernel_write_ptr = NULL;
static filp_close_t filp_close_ptr = NULL;

/* ---------- 哈希函数 ---------- */
static u64 hash_signature(int fd, loff_t pos, size_t count,
                          const unsigned char *data, int data_len)
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

/* ---------- 安全读取数据样本 ---------- */
static void read_data_sample(const void __user *buf, size_t count,
                             unsigned char *out, int *out_len)
{
    if (!buf || count == 0) { *out_len = 0; return; }
    int len = count < 8 ? count : 8;
    if (compat_strncpy_from_user((char *)out, (const char __user *)buf, len) > 0)
        *out_len = len;
    else
        *out_len = 0;
}

/* ---------- 十六进制打印 ---------- */
static void print_hex(const unsigned char *data, int len)
{
    for (int i = 0; i < len; i++)
        printk(KERN_INFO " %02x", data[i]);
}

/* ---------- CTL0 控制 ---------- */
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
        target_pid = 0;
        fd_max = 0;
        printk(KERN_INFO "KMS: stopped, filters cleared\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "stopped+cleared", outlen);
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
    } else if (strncmp(args, "fmt=", 4) == 0) {
        const char *p = args + 4;
        int val = 0;
        while (*p >= '0' && *p <= '9') val = val * 10 + (*p++ - '0');
        if (*p != '\0' || (val != 0 && val != 1)) {
            if (out_msg && outlen > 0) strncpy(out_msg, "err", outlen);
            return -EINVAL;
        }
        output_format = val;
        printk(KERN_INFO "KMS: output format set to %d\n", output_format);
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    } else {
        if (out_msg && outlen > 0) strncpy(out_msg, "unknown", outlen);
    }
    return 0;
}

/* ---------- pread64 Hook ---------- */
static void before_pread64(hook_fargs4_t *fargs, void *udata)
{
    int fd = (int)syscall_argn(fargs, 0);
    void __user *buf = (void __user *)syscall_argn(fargs, 1);
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
            if (output_format == 1) {
                printk(KERN_INFO "KMS| pread64(%d, 0x%x, %zu, 0x%llx)\n",
                       fd, buf, count, pos);
            } else {
                printk(KERN_INFO "KMS| pread64 | FD=%d BUF=%px COUNT=%zu POS=0x%llx",
                       fd, buf, count, pos);
                if (sample_len > 0) {
                    printk(KERN_INFO " DATA=");
                    print_hex(sample, sample_len);
                }
                printk(KERN_INFO "\n");
            }
        }
    }
}

/* ---------- pwrite64 Hook ---------- */
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
            if (output_format == 1) {
                printk(KERN_INFO "KMS| pwrite64(%d, 0x%x, %zu, 0x%llx)\n",
                       fd, buf, count, pos);
            } else {
                printk(KERN_INFO "KMS| pwrite64 | FD=%d BUF=%px COUNT=%zu POS=0x%llx",
                       fd, buf, count, pos);
                if (sample_len > 0) {
                    printk(KERN_INFO " DATA=");
                    print_hex(sample, sample_len);
                }
                printk(KERN_INFO "\n");
            }
        }
    }
}

/* ---------- process_vm_readv Hook ---------- */
static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid <= 0 || tpid != target_pid) return;
    printk(KERN_INFO "KMS| process_vm_readv | TARGET=%d\n", tpid);
}

/* ---------- process_vm_writev Hook ---------- */
static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid <= 0 || tpid != target_pid) return;
    printk(KERN_INFO "KMS| process_vm_writev | TARGET=%d\n", tpid);
}

/* ---------- 初始化 ---------- */
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

    /* 动态获取文件操作函数 */
    filp_open_ptr = (filp_open_t)kallsyms_lookup_name("filp_open");
    kernel_write_ptr = (kernel_write_t)kallsyms_lookup_name("kernel_write");
    filp_close_ptr = (filp_close_t)kallsyms_lookup_name("filp_close");

    /* 创建状态文件 */
    if (filp_open_ptr && kernel_write_ptr && filp_close_ptr) {
        struct file *fp = filp_open_ptr("/data/local/tmp/kms_loaded",
                                        O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (!IS_ERR(fp)) {
            char msg[] = "loaded";
            loff_t pos = 0;
            kernel_write_ptr(fp, msg, sizeof(msg), &pos);
            filp_close_ptr(fp, NULL);
            printk(KERN_INFO "KMS: status file created\n");
        }
    }

    printk(KERN_INFO "KMS: loaded (v6.4.3, fmt=%d)\n", output_format);
    return 0;
}

/* ---------- 卸载 ---------- */
static long interceptr_exit(void *__user reserved)
{
    fp_unhook_syscalln(__NR_pread64, before_pread64, 0);
    fp_unhook_syscalln(__NR_pwrite64, before_pwrite64, 0);
    fp_unhook_syscalln(__NR_process_vm_readv, before_process_vm_readv, 0);
    fp_unhook_syscalln(__NR_process_vm_writev, before_process_vm_writev, 0);

    /* 清空状态文件内容（截断） */
    if (filp_open_ptr && filp_close_ptr) {
        struct file *fp = filp_open_ptr("/data/local/tmp/kms_loaded",
                                        O_WRONLY | O_TRUNC, 0);
        if (!IS_ERR(fp)) {
            filp_close_ptr(fp, NULL);
            printk(KERN_INFO "KMS: status file truncated\n");
        }
    }

    printk(KERN_INFO "KMS: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(interceptr_exit);
KPM_CTL0(interceptor_control0);