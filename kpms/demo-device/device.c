/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * 设备文件测试模块 - 验证 /dev/kms_intercept 能否创建
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("DeviceTest");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Test misc device creation");

/* 手动定义 miscdevice 结构体（头文件可能不全） */
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

/* 我们需要的 file_operations 只需要一个 owner 占位 */
struct file_operations {
    struct module *owner;
};

static struct file_operations test_fops = {
    .owner = NULL,  // 表示无所有者，仅测试
};

static struct miscdevice test_misc = {
    .minor = 255,            // 动态分配
    .name = "kms_intercept",
    .fops = &test_fops,
};

/* 动态查找 misc_register */
typedef int (*misc_register_t)(struct miscdevice *);
static misc_register_t misc_register_ptr = NULL;

typedef void (*misc_deregister_t)(struct miscdevice *);
static misc_deregister_t misc_deregister_ptr = NULL;

static long init(const char *args, const char *event, void *__user reserved)
{
    misc_register_ptr = (misc_register_t)kallsyms_lookup_name("misc_register");
    misc_deregister_ptr = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");

    if (!misc_register_ptr || !misc_deregister_ptr) {
        printk(KERN_ERR "DeviceTest: misc_register/deregister not found\n");
        return -1;
    }

    int ret = misc_register_ptr(&test_misc);
    if (ret < 0) {
        printk(KERN_ERR "DeviceTest: misc_register failed %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "DeviceTest: /dev/%s created, minor=%d\n", test_misc.name, test_misc.minor);
    return 0;
}

static long exit(void *__user reserved)
{
    if (misc_deregister_ptr)
        misc_deregister_ptr(&test_misc);
    printk(KERN_INFO "DeviceTest: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);