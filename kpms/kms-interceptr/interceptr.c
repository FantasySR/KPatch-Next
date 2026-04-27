/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - System Call Interceptor
 * Hooks: pread64, pwrite64, process_vm_readv, process_vm_writev
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
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Interceptor for pread64/pwrite64/process_vm_readv/writev");

/* 前向声明 struct pid_namespace, 避免编译器报警 */
struct pid_namespace;

/* 动态查找的函数指针 — 类型改为 int 绕过 enum 类型缺失 */
static pid_t (*__task_pid_nr_ns)(struct task_struct *task, int type, struct pid_namespace *ns) = NULL;

/* 自定义 iovec 结构体 */
struct kms_iovec {
    void __user *iov_base;
    unsigned long iov_len;
};

/* PID 类型常量 (与内核保持一致) */
#define KMSPID_PID   0
#define KMSPID_TGID  1

/* ---- pread64 (fd, buf, count, pos) ---- */
static void before_pread64(hook_fargs4_t *fargs, void *udata)
{
    int fd = (int)syscall_argn(fargs, 0);
    void __user *buf = (void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_PID, NULL) : -1;
    pid_t tgid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_TGID, NULL) : -1;

    printk(KERN_INFO "KMS| pread64 | PID=%d TGID=%d FD=%d BUF=%px COUNT=%zu POS=%lld\n",
           pid, tgid, fd, buf, count, pos);

    if (buf && count > 0) {
        unsigned char tmp[32];
        unsigned long len = count < 32 ? count : 32;
        if (compat_strncpy_from_user(tmp, (const char __user *)buf, len) > 0) {
            printk(KERN_INFO "KMS| pread64 DATA: %*phN\n", (int)len, tmp);
        }
    }
}

/* ---- pwrite64 ---- */
static void before_pwrite64(hook_fargs4_t *fargs, void *udata)
{
    int fd = (int)syscall_argn(fargs, 0);
    const void __user *buf = (const void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_PID, NULL) : -1;
    pid_t tgid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_TGID, NULL) : -1;

    printk(KERN_INFO "KMS| pwrite64 | PID=%d TGID=%d FD=%d BUF=%px COUNT=%zu POS=%lld\n",
           pid, tgid, fd, buf, count, pos);

    if (buf && count > 0) {
        unsigned char tmp[32];
        unsigned long len = count < 32 ? count : 32;
        if (compat_strncpy_from_user(tmp, (const char __user *)buf, len) > 0) {
            printk(KERN_INFO "KMS| pwrite64 DATA: %*phN\n", (int)len, tmp);
        }
    }
}

/* ---- process_vm_readv ---- */
static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata)
{
    pid_t target_pid = (pid_t)syscall_argn(fargs, 0);
    void __user *local_iov = (void __user *)syscall_argn(fargs, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(fargs, 2);
    void __user *remote_iov = (void __user *)syscall_argn(fargs, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(fargs, 4);
    unsigned long flags = (unsigned long)syscall_argn(fargs, 5);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_PID, NULL) : -1;
    pid_t tgid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_TGID, NULL) : -1;

    printk(KERN_INFO "KMS| process_vm_readv | PID=%d TGID=%d TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
           pid, tgid, target_pid, local_iov, liovcnt, remote_iov, riovcnt, flags);

    if (local_iov && liovcnt > 0) {
        struct kms_iovec __user *local_vec = (struct kms_iovec __user *)local_iov;
        struct kms_iovec vec;
        if (compat_strncpy_from_user((char *)&vec, (const char __user *)local_vec, sizeof(vec)) == sizeof(vec)) {
            if (vec.iov_base && vec.iov_len > 0) {
                unsigned char tmp[32];
                unsigned long len = vec.iov_len < 32 ? vec.iov_len : 32;
                if (compat_strncpy_from_user((char *)tmp, (const char __user *)vec.iov_base, len) > 0) {
                    printk(KERN_INFO "KMS| process_vm_readv DATA(local): %*phN\n", (int)len, tmp);
                }
            }
        }
    }
}

/* ---- process_vm_writev ---- */
static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata)
{
    pid_t target_pid = (pid_t)syscall_argn(fargs, 0);
    void __user *local_iov = (void __user *)syscall_argn(fargs, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(fargs, 2);
    void __user *remote_iov = (void __user *)syscall_argn(fargs, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(fargs, 4);
    unsigned long flags = (unsigned long)syscall_argn(fargs, 5);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_PID, NULL) : -1;
    pid_t tgid = __task_pid_nr_ns ? __task_pid_nr_ns(task, KMSPID_TGID, NULL) : -1;

    printk(KERN_INFO "KMS| process_vm_writev | PID=%d TGID=%d TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
           pid, tgid, target_pid, local_iov, liovcnt, remote_iov, riovcnt, flags);

    if (local_iov && liovcnt > 0) {
        struct kms_iovec __user *local_vec = (struct kms_iovec __user *)local_iov;
        struct kms_iovec vec;
        if (compat_strncpy_from_user((char *)&vec, (const char __user *)local_vec, sizeof(vec)) == sizeof(vec)) {
            if (vec.iov_base && vec.iov_len > 0) {
                unsigned char tmp[32];
                unsigned long len = vec.iov_len < 32 ? vec.iov_len : 32;
                if (compat_strncpy_from_user((char *)tmp, (const char __user *)vec.iov_base, len) > 0) {
                    printk(KERN_INFO "KMS| process_vm_writev DATA(local): %*phN\n", (int)len, tmp);
                }
            }
        }
    }
}

/* ---- 初始化 & 退出 ---- */
static long init(const char *args, const char *event, void *__user reserved)
{
    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    pr_info("KMS: __task_pid_nr_ns addr: %px\n", __task_pid_nr_ns);

    hook_err_t err;

    err = fp_hook_syscalln(__NR_pread64, 4, before_pread64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pread64 failed %d\n", err);

    err = fp_hook_syscalln(__NR_pwrite64, 4, before_pwrite64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pwrite64 failed %d\n", err);

    err = fp_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_readv failed %d\n", err);

    err = fp_hook_syscalln(__NR_process_vm_writev, 6, before_process_vm_writev, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_writev failed %d\n", err);

    printk(KERN_INFO "KernelMemorySky: loaded, hooks installed\n");
    return 0;
}

static long interceptr_exit(void *__user reserved)
{
    fp_unhook_syscalln(__NR_pread64, before_pread64, 0);
    fp_unhook_syscalln(__NR_pwrite64, before_pwrite64, 0);
    fp_unhook_syscalln(__NR_process_vm_readv, before_process_vm_readv, 0);
    fp_unhook_syscalln(__NR_process_vm_writev, before_process_vm_writev, 0);
    printk(KERN_INFO "KernelMemorySky: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(interceptr_exit);