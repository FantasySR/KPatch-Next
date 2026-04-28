/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>

KPM_NAME("DeviceTest");
KPM_VERSION("0.9.4");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Last attempt with full fops");

#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif

/* 尽可能完整的 file_operations 结构体定义（基于 Linux 5.15 ARM64） */
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
    int (*iopoll)(struct kiocb *kiocb, bool spin);
    int (*iterate) (struct file *, struct dir_context *);
    int (*iterate_shared) (struct file *, struct dir_context *);
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    int (*mmap) (struct file *, struct vm_area_struct *);
    unsigned long mmap_supported_flags;
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id);
    int (*release) (struct inode *, struct file *);
    int (*fsync) (struct file *, loff_t, loff_t, int datasync);
    int (*fasync) (int, struct file *, int);
    int (*lock) (struct file *, int, struct file_lock *);
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock) (struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *file, int mode, loff_t offset, loff_t len);
    void (*show_fdinfo)(struct seq_file *m, struct file *f);
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
    loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out, loff_t len, unsigned int remap_flags);
    int (*fadvise)(struct file *, loff_t, loff_t, int);
} __randomize_layout;

struct miscdevice {
    int minor;
    const char *name;
    const struct file_operations *fops;
    struct list_head list;
    struct device *parent;
    struct device *this_device;
    const struct attribute_group **groups;
    const char *nodename;
    umode_t mode;
};

/* 动态函数指针 */
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);
static copy_to_user_t copy_to_user_ptr = NULL;

static ssize_t dev_read(struct file *file, char __user *buf, size_t len, loff_t *off) {
    printk(KERN_INFO "DeviceTest: dev_read called\n");
    const char *msg = "KMS active\n";
    size_t msg_len = strlen(msg);
    if (*off >= msg_len) return 0;
    size_t to_copy = (len < msg_len - *off) ? len : (msg_len - *off);
    if (copy_to_user_ptr) {
        if (copy_to_user_ptr(buf, msg + *off, to_copy)) {
            printk(KERN_INFO "DeviceTest: copy_to_user failed\n");
            return -EFAULT;
        }
    } else {
        printk(KERN_INFO "DeviceTest: copy_to_user_ptr is NULL\n");
        return 0;
    }
    *off += to_copy;
    return to_copy;
}

static int dev_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "DeviceTest: open called\n");
    return 0;
}
static int dev_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "DeviceTest: release called\n");
    return 0;
}

static struct file_operations fops = {
    .owner = NULL,
    .llseek = NULL,
    .read = dev_read,
    .write = NULL,
    .read_iter = NULL,
    .write_iter = NULL,
    .iopoll = NULL,
    .iterate = NULL,
    .iterate_shared = NULL,
    .poll = NULL,
    .unlocked_ioctl = NULL,
    .compat_ioctl = NULL,
    .mmap = NULL,
    .mmap_supported_flags = 0,
    .open = dev_open,
    .flush = NULL,
    .release = dev_release,
    .fsync = NULL,
    .fasync = NULL,
    .lock = NULL,
    .sendpage = NULL,
    .get_unmapped_area = NULL,
    .check_flags = NULL,
    .flock = NULL,
    .splice_write = NULL,
    .splice_read = NULL,
    .setlease = NULL,
    .fallocate = NULL,
    .show_fdinfo = NULL,
    .copy_file_range = NULL,
    .remap_file_range = NULL,
    .fadvise = NULL,
};

static struct miscdevice dev_misc = {
    .minor = 255,
    .name = "kms_intercept",
    .fops = &fops,
};

/* CTL0 控制 */
static long ct0_handler(const char *args, char *__user out_msg, int outlen) {
    if (!args) {
        if (out_msg && outlen > 0) strncpy(out_msg, "no cmd", outlen);
        return 0;
    }
    if (strcmp(args, "run") == 0) {
        printk(KERN_INFO "KMS: run command received\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "running", outlen);
    } else if (strcmp(args, "stop") == 0) {
        printk(KERN_INFO "KMS: stop command received\n");
        if (out_msg && outlen > 0) strncpy(out_msg, "stopped", outlen);
    } else {
        printk(KERN_INFO "KMS: unknown command: %s\n", args);
        if (out_msg && outlen > 0) strncpy(out_msg, "unknown", outlen);
    }
    return 0;
}

typedef int (*misc_register_t)(struct miscdevice *);
typedef void (*misc_deregister_t)(struct miscdevice *);
static misc_register_t misc_reg = NULL;
static misc_deregister_t misc_dereg = NULL;

static long init(const char *args, const char *event, void *__user reserved) {
    misc_reg = (misc_register_t)kallsyms_lookup_name("misc_register");
    misc_dereg = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");
    if (!misc_reg || !misc_dereg) {
        printk(KERN_ERR "DeviceTest: misc symbols not found\n");
        return -1;
    }
    copy_to_user_ptr = (copy_to_user_t)kallsyms_lookup_name("copy_to_user_nofault");
    if (!copy_to_user_ptr) {
        printk(KERN_WARNING "DeviceTest: copy_to_user_nofault not found, read disabled\n");
    }

    int ret = misc_reg(&dev_misc);
    if (ret < 0) {
        printk(KERN_ERR "DeviceTest: register failed %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "DeviceTest: /dev/%s ready\n", dev_misc.name);
    return 0;
}

static long exit(void *__user reserved) {
    if (misc_dereg) misc_dereg(&dev_misc);
    printk(KERN_INFO "DeviceTest: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);
KPM_CTL0(ct0_handler);