/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * 设备文件 - 极简只读验证
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

KPM_NAME("DeviceTest");
KPM_VERSION("0.9.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Read-only misc device + CTL0 control");

/* 手动补充宏 */
#ifndef EFAULT
#define EFAULT 14
#endif

/* 结构体定义 */
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

struct file_operations {
    struct module *owner;
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    int (*open)(struct inode *, struct file *);
    int (*release)(struct inode *, struct file *);
};

/* ---- 设备操作 ---- */
static int dev_open(struct inode *inode, struct file *file) { return 0; }
static int dev_release(struct inode *inode, struct file *file) { return 0; }

static ssize_t dev_read(struct file *file, char __user *buf, size_t len, loff_t *off) {
    const char *msg = "KMS active\n";
    size_t msg_len = strlen(msg);
    if (*off >= msg_len) return 0;
    size_t to_copy = (len < msg_len - *off) ? len : (msg_len - *off);
    // 直接调用内核中可用的 copy_to_user (已验证存在)
    if (copy_to_user(buf, msg + *off, to_copy)) return -EFAULT;
    *off += to_copy;
    return to_copy;
}

static struct file_operations fops = {
    .owner = NULL,
    .open = dev_open,
    .release = dev_release,
    .read = dev_read,
};

static struct miscdevice dev_misc = {
    .minor = 255,
    .name = "kms_intercept",
    .fops = &fops,
};

/* ---- CTL0 控制（通过调参发送命令）---- */
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

/* ---- 动态注册 ---- */
typedef int (*misc_register_t)(struct miscdevice *);
typedef void (*misc_deregister_t)(struct miscdevice *);
static misc_register_t misc_reg = NULL;
static misc_deregister_t misc_dereg = NULL;

static long init(const char *args, const char *event, void *__user reserved) {
    misc_reg = (misc_register_t)kallsyms_lookup_name("misc_register");
    misc_dereg = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");
    if (!misc_reg || !misc_dereg) {
        printk(KERN_ERR "DeviceTest: symbols missing\n");
        return -1;
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