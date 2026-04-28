/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * 设备文件测试模块 - 验证读写功能
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>

KPM_NAME("DeviceTest");
KPM_VERSION("1.1.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Test misc device with read/write");

/* ---- 手动补充缺失的宏和声明 ---- */
#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef GFP_KERNEL
#define GFP_KERNEL 0xcc0U
#endif

extern unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);
extern unsigned long copy_from_user(void *to, const void __user *from, unsigned long n);

/* ---- 手动定义必要结构体 ---- */
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
    loff_t (*llseek)(struct file *, loff_t, int);
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
    int (*open)(struct inode *, struct file *);
    int (*release)(struct inode *, struct file *);
};

/* ---- 环形缓冲区 ---- */
#define BUF_SIZE (1024 * 1024)  // 1MB
static char *ring_buf = NULL;
static size_t ring_head = 0;
static size_t ring_tail = 0;
static size_t ring_count = 0;

/* ---- 内核函数动态引用 ---- */
typedef int (*misc_register_t)(struct miscdevice *);
typedef void (*misc_deregister_t)(struct miscdevice *);
static misc_register_t misc_register_ptr = NULL;
static misc_deregister_t misc_deregister_ptr = NULL;

/* ---- 设备操作实现 ---- */
static int dev_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "DeviceTest: device opened\n");
    return 0;
}

static int dev_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "DeviceTest: device closed\n");
    return 0;
}

static ssize_t dev_read(struct file *file, char __user *buf, size_t len, loff_t *off) {
    size_t available = ring_count;
    if (available == 0) return 0;

    size_t to_copy = (len < available) ? len : available;
    size_t first_chunk = (ring_tail + to_copy <= BUF_SIZE) ? to_copy : (BUF_SIZE - ring_tail);

    if (copy_to_user(buf, ring_buf + ring_tail, first_chunk)) {
        return -EFAULT;
    }
    if (to_copy > first_chunk) {
        if (copy_to_user(buf + first_chunk, ring_buf, to_copy - first_chunk)) {
            return -EFAULT;
        }
    }

    ring_tail = (ring_tail + to_copy) % BUF_SIZE;
    ring_count -= to_copy;
    return to_copy;
}

static ssize_t dev_write(struct file *file, const char __user *buf, size_t len, loff_t *off) {
    char kb[128];
    size_t l = len < sizeof(kb)-1 ? len : sizeof(kb)-1;
    if (copy_from_user(kb, buf, l)) return -EFAULT;
    kb[l] = '\0';

    printk(KERN_INFO "DeviceTest: received command: %s\n", kb);
    // 把命令写入环形缓冲区作为回显
    size_t cmd_len = strlen(kb);
    for (size_t i = 0; i < cmd_len; i++) {
        ring_buf[ring_head] = kb[i];
        ring_head = (ring_head + 1) % BUF_SIZE;
        if (ring_count < BUF_SIZE) ring_count++;
    }
    ring_buf[ring_head] = '\n';
    ring_head = (ring_head + 1) % BUF_SIZE;
    if (ring_count < BUF_SIZE) ring_count++;

    return len;
}

static struct file_operations fops = {
    .owner = NULL,
    .open = dev_open,
    .release = dev_release,
    .read = dev_read,
    .write = dev_write,
};

static struct miscdevice dev_misc = {
    .minor = 255,
    .name = "kms_intercept",
    .fops = &fops,
};

/* ---- 模块生命周期 ---- */
static long init(const char *args, const char *event, void *__user reserved)
{
    misc_register_ptr = (misc_register_t)kallsyms_lookup_name("misc_register");
    misc_deregister_ptr = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");
    if (!misc_register_ptr || !misc_deregister_ptr) {
        printk(KERN_ERR "DeviceTest: symbol lookup failed\n");
        return -1;
    }

    ring_buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!ring_buf) {
        printk(KERN_ERR "DeviceTest: buffer allocation failed\n");
        return -ENOMEM;
    }

    int ret = misc_register_ptr(&dev_misc);
    if (ret < 0) {
        kfree(ring_buf);
        printk(KERN_ERR "DeviceTest: misc_register failed %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "DeviceTest: /dev/%s created, minor=%d\n", dev_misc.name, dev_misc.minor);
    return 0;
}

static long dev_exit(void *__user reserved)
{
    if (misc_deregister_ptr) misc_deregister_ptr(&dev_misc);
    if (ring_buf) kfree(ring_buf);
    printk(KERN_INFO "DeviceTest: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(dev_exit);