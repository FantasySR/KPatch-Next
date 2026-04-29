/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelMemorySky - v6.4.2 (文件内容清空，用户态内容检测)
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
KPM_VERSION("6.4.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Interceptor with content-based status detection");

/* ---------- 补充宏 ---------- */
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
static int learn_mode = 1;
static int output_format = 0;
static int target_pid = 0;
static int fd_max = 0;

static filp_open_t filp_open_ptr = NULL;
static kernel_write_t kernel_write_ptr = NULL;
static filp_close_t filp_close_ptr = NULL;

/* ... (哈希函数、CTL0、Hook 等与之前版本完全相同，此处省略以节省篇幅) ... */
/* 请务必将之前完整代码中对应的函数（hash_signature, is_signature_present, insert_signature,
   clear_table, read_data_sample, print_hex, interceptor_control0, 
   before_pread64, before_pwrite64, before_process_vm_readv, before_process_vm_writev）
   完整保留并放在这里 */

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

    filp_open_ptr = (filp_open_t)kallsyms_lookup_name("filp_open");
    kernel_write_ptr = (kernel_write_t)kallsyms_lookup_name("kernel_write");
    filp_close_ptr = (filp_close_t)kallsyms_lookup_name("filp_close");

    if (filp_open_ptr && kernel_write_ptr && filp_close_ptr) {
        struct file *fp = filp_open_ptr("/data/local/tmp/kms_loaded",
                                        O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (!IS_ERR(fp)) {
            char msg[] = "loaded";
            loff_t pos = 0;
            kernel_write_ptr(fp, msg, sizeof(msg), &pos);
            filp_close_ptr(fp, NULL);
            printk(KERN_INFO "KMS: status file created\n");
        } else {
            printk(KERN_ERR "KMS: could not create status file\n");
        }
    }

    printk(KERN_INFO "KMS: loaded (v6.4.2, fmt=%d)\n", output_format);
    return 0;
}

/* ---------- 模块卸载 ---------- */
static long interceptr_exit(void *__user reserved)
{
    fp_unhook_syscalln(__NR_pread64, before_pread64, 0);
    fp_unhook_syscalln(__NR_pwrite64, before_pwrite64, 0);
    fp_unhook_syscalln(__NR_process_vm_readv, before_process_vm_readv, 0);
    fp_unhook_syscalln(__NR_process_vm_writev, before_process_vm_writev, 0);

    /* 清空状态文件内容 (截断为 0 字节) */
    if (filp_open_ptr && filp_close_ptr) {
        struct file *fp = filp_open_ptr("/data/local/tmp/kms_loaded",
                                        O_WRONLY | O_TRUNC, 0);
        if (!IS_ERR(fp)) {
            filp_close_ptr(fp, NULL);
            printk(KERN_INFO "KMS: status file truncated\n");
        } else {
            printk(KERN_ERR "KMS: could not truncate status file\n");
        }
    }

    printk(KERN_INFO "KMS: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(interceptr_exit);
KPM_CTL0(interceptor_control0);