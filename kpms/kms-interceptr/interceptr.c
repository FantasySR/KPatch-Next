/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - System Call Interceptor
 * Hooks: pread64, pwrite64, process_vm_readv, process_vm_writev
 * PID filter: directly reads current->pid (auto-calibrated offset)
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
KPM_VERSION("3.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("PID filter using current->pid auto-offset");

/* 自定义 iovec */
struct kms_iovec {
    void __user *iov_base;
    unsigned long iov_len;
};

/* 动态内核函数指针 (保留 f_owner 相关，但仅作可选) */
static struct file *(*fget_ptr)(unsigned int fd) = NULL;
static void (*fput_ptr)(struct file *) = NULL;
static int (*f_setown_ptr)(struct file *, pid_t, int) = NULL;

/* 全局变量 */
static int target_pid = 0;
static int task_pid_offset = -1;   // current->pid 的偏移量，动态检测

/* ---- 动态检测 current->pid 偏移量 ---- */
static void detect_task_pid_offset(void)
{
    struct task_struct *init = (struct task_struct *)kallsyms_lookup_name("init_task");
    if (!init) {
        printk(KERN_ERR "KMS: init_task not found, fallback to f_owner if available\n");
        return;
    }

    // 扫描 init_task 结构体，查找值为 1 的 int (因为 init 进程的 pid 是 1)
    int i;
    for (i = 0x100; i <= 0x400; i += 4) {
        int val = *(int *)((unsigned long)init + i);
        if (val == 1) {
            // 初步找到可能的 pid 字段，进一步验证：检查下一个 int 是否是 tgid (也是 1)
            int val2 = *(int *)((unsigned long)init + i + 4);
            if (val2 == 1) {
                task_pid_offset = i;
                printk(KERN_INFO "KMS: detected current->pid offset = 0x%x\n", i);
                return;
            }
        }
    }

    printk(KERN_WARNING "KMS: could not auto-detect pid offset, using default 0x448\n");
    task_pid_offset = 0x448; // ARM64 常见值
}

/* ---- CTL0 控制接口 (支持 so, ofs=, off, PID) ---- */
static long interceptor_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args) {
        if (out_msg && outlen > 0) {
            if (target_pid == 0)
                strncpy(out_msg, "filter off", outlen);
            else
                strncpy(out_msg, "filter on", outlen);
        }
        return 0;
    }

    /* so<pid>：仅供测试 f_owner 使用 (可选) */
    if (strncmp(args, "so", 2) == 0) {
        if (!f_setown_ptr || !fget_ptr || !fput_ptr) {
            if (out_msg && outlen > 0) strncpy(out_msg, "err: no f_setown", outlen);
            return -ENOSYS;
        }
        const char *p = args + 2;
        int owner_pid = 0;
        while (*p >= '0' && *p <= '9') owner_pid = owner_pid * 10 + (*p++ - '0');
        if (owner_pid <= 0) {
            if (out_msg && outlen > 0) strncpy(out_msg, "err", outlen);
            return -EINVAL;
        }
        for (int fd = 0; fd < 1024; fd++) {
            struct file *filp = fget_ptr(fd);
            if (!filp) continue;
            f_setown_ptr(filp, owner_pid, 0);
            fput_ptr(filp);
        }
        printk(KERN_INFO "KMS: f_setown executed for pid %d\n", owner_pid);
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
        return 0;
    }

    /* off */
    if (strcmp(args, "off") == 0) {
        target_pid = 0;
        printk(KERN_INFO "KMS: PID filter disabled\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
        return 0;
    }

    /* 数字：设置过滤 PID */
    int pid = 0;
    const char *p = args;
    if (*p == '-') {
        if (out_msg && outlen > 0) strncpy(out_msg, "err", outlen);
        return -EINVAL;
    }
    while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
    if (*p != '\0') {
        if (out_msg && outlen > 0) strncpy(out_msg, "err", outlen);
        return -EINVAL;
    }
    target_pid = pid;
    printk(KERN_INFO "KMS: PID filter set to %d\n", target_pid);
    if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    return 0;
}

/* ---- 辅助：从 current 读取调用者 PID ---- */
static inline pid_t get_current_pid(void)
{
    if (task_pid_offset <= 0) return -1;
    return *(int *)((unsigned long)current + task_pid_offset);
}

/* ---- pread64 (使用 current->pid 过滤) ---- */
static void before_pread64(hook_fargs4_t *fargs, void *udata)
{
    pid_t caller_pid = get_current_pid();
    if (target_pid > 0 && caller_pid != -1 && caller_pid != target_pid)
        return;

    int fd = (int)syscall_argn(fargs, 0);
    void __user *buf = (void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    printk(KERN_INFO "KMS| pread64 | PID=%d FD=%d BUF=%px COUNT=%zu POS=%lld\n",
           caller_pid, fd, buf, count, pos);

    if (buf && count > 0) {
        unsigned char tmp[32];
        unsigned long len = count < 32 ? count : 32;
        if (compat_strncpy_from_user(tmp, (const char __user *)buf, len) > 0) {
            printk(KERN_INFO "KMS| pread64 DATA: %*phN\n", (int)len, tmp);
        }
    }
}

/* ---- pwrite64 (使用 current->pid 过滤) ---- */
static void before_pwrite64(hook_fargs4_t *fargs, void *udata)
{
    pid_t caller_pid = get_current_pid();
    if (target_pid > 0 && caller_pid != -1 && caller_pid != target_pid)
        return;

    int fd = (int)syscall_argn(fargs, 0);
    const void __user *buf = (const void __user *)syscall_argn(fargs, 1);
    size_t count = (size_t)syscall_argn(fargs, 2);
    loff_t pos = (loff_t)syscall_argn(fargs, 3);

    printk(KERN_INFO "KMS| pwrite64 | PID=%d FD=%d BUF=%px COUNT=%zu POS=%lld\n",
           caller_pid, fd, buf, count, pos);

    if (buf && count > 0) {
        unsigned char tmp[32];
        unsigned long len = count < 32 ? count : 32;
        if (compat_strncpy_from_user(tmp, (const char __user *)buf, len) > 0) {
            printk(KERN_INFO "KMS| pwrite64 DATA: %*phN\n", (int)len, tmp);
        }
    }
}

/* ---- process_vm_readv (目标 PID 过滤，不变) ---- */
static void before_process_vm_readv(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid > 0 && tpid != target_pid)
        return;

    void __user *local_iov = (void __user *)syscall_argn(fargs, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(fargs, 2);
    void __user *remote_iov = (void __user *)syscall_argn(fargs, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(fargs, 4);
    unsigned long flags = (unsigned long)syscall_argn(fargs, 5);

    printk(KERN_INFO "KMS| process_vm_readv | TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
           tpid, local_iov, liovcnt, remote_iov, riovcnt, flags);

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

/* ---- process_vm_writev (目标 PID 过滤，不变) ---- */
static void before_process_vm_writev(hook_fargs6_t *fargs, void *udata)
{
    pid_t tpid = (pid_t)syscall_argn(fargs, 0);
    if (target_pid > 0 && tpid != target_pid)
        return;

    void __user *local_iov = (void __user *)syscall_argn(fargs, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(fargs, 2);
    void __user *remote_iov = (void __user *)syscall_argn(fargs, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(fargs, 4);
    unsigned long flags = (unsigned long)syscall_argn(fargs, 5);

    printk(KERN_INFO "KMS| process_vm_writev | TARGET=%d LIOV=%px LCNT=%lu RIOV=%px RCNT=%lu FLAGS=%lu\n",
           tpid, local_iov, liovcnt, remote_iov, riovcnt, flags);

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

/* ---- 初始化 ---- */
static long init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;

    /* 检测 current->pid 偏移 */
    detect_task_pid_offset();

    /* 获取 f_owner 相关函数 (可选) */
    fget_ptr = (typeof(fget_ptr))kallsyms_lookup_name("fget");
    fput_ptr = (typeof(fput_ptr))kallsyms_lookup_name("fput");
    f_setown_ptr = (typeof(f_setown_ptr))kallsyms_lookup_name("f_setown");

    /* 安装钩子 */
    err = fp_hook_syscalln(__NR_pread64, 4, before_pread64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pread64 failed %d\n", err);

    err = fp_hook_syscalln(__NR_pwrite64, 4, before_pwrite64, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook pwrite64 failed %d\n", err);

    err = fp_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_readv failed %d\n", err);

    err = fp_hook_syscalln(__NR_process_vm_writev, 6, before_process_vm_writev, 0, 0);
    if (err) printk(KERN_ERR "KMS: hook process_vm_writev failed %d\n", err);

    printk(KERN_INFO "KMS: loaded, pid offset=0x%x\n", task_pid_offset);
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