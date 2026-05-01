/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>

KPM_NAME("NetlinkDemo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Netlink send test");

/* 手动补充 errno */
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EIO
#define EIO   5
#endif

#define NETLINK_TEST 31
#define GFP_ATOMIC 0x20U

/* 手动定义 Netlink 的必要结构体和宏 */
struct nlmsghdr {
    __u32 nlmsg_len;
    __u16 nlmsg_type;
    __u16 nlmsg_flags;
    __u32 nlmsg_seq;
    __u32 nlmsg_pid;
};

#define NLMSG_ALIGNTO    4
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN     ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_ALIGN(NLMSG_HDRLEN))
#define NLMSG_SPACE(len)  NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh)   ((void *)(((char *)(nlh)) + NLMSG_LENGTH(0)))
#define NLMSG_DONE 3

struct netlink_kernel_cfg {
    void (*input)(void *);
};

/* 函数指针类型（全部使用 void* 或 unsigned long 兼容） */
typedef void *(*nl_create_t)(void *, int, struct netlink_kernel_cfg *);
typedef void (*nl_release_t)(void *);
typedef void *(*alloc_skb_t)(unsigned int, gfp_t);
typedef void (*kfree_skb_t)(void *);
typedef int (*nl_unicast_t)(void *, void *, u32);
typedef void *(*nl_put_t)(void *, u32, u32, int, int, int);
typedef void (*nl_end_t)(void *, void *);

/* 全局函数指针 */
static nl_create_t __nl_create = NULL;
static nl_release_t __nl_release = NULL;
static alloc_skb_t __alloc_skb = NULL;
static kfree_skb_t __kfree_skb = NULL;
static nl_unicast_t __nl_unicast = NULL;
static nl_put_t __nl_put = NULL;
static nl_end_t __nl_end = NULL;

static void *nl_sk = NULL;
static void *init_net_ptr = NULL;

/* CTL0：传入目标 PID，发送一条消息 */
static long netlink_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args || !nl_sk) {
        if (out_msg && outlen > 0) strncpy(out_msg, "not ready", outlen);
        return 0;
    }

    int target_pid = 0;
    const char *p = args;
    while (*p >= '0' && *p <= '9') target_pid = target_pid * 10 + (*p++ - '0');
    if (*p != '\0' || target_pid <= 0) {
        if (out_msg && outlen > 0) strncpy(out_msg, "err:bad pid", outlen);
        return -EINVAL;
    }

    void *skb = __alloc_skb(NLMSG_SPACE(32), GFP_ATOMIC);
    if (!skb) {
        if (out_msg && outlen > 0) strncpy(out_msg, "err:alloc", outlen);
        return -ENOMEM;
    }

    void *nlh = __nl_put(skb, 0, 0, NLMSG_DONE, 32, 0);
    if (!nlh) {
        __kfree_skb(skb);
        if (out_msg && outlen > 0) strncpy(out_msg, "err:put", outlen);
        return -ENOMEM;
    }

    const char *msg = "Hello from Kernel!";
    memcpy(NLMSG_DATA(nlh), msg, strlen(msg) + 1);
    __nl_end(skb, nlh);

    if (__nl_unicast(nl_sk, skb, target_pid) < 0) {
        if (out_msg && outlen > 0) strncpy(out_msg, "err:send", outlen);
        return -EIO;
    }

    printk(KERN_INFO "NL_DEMO: sent to pid %d\n", target_pid);
    if (out_msg && outlen > 0) strncpy(out_msg, "ok", outlen);
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved)
{
    /* 获取 init_net 地址（符号名就是 init_net） */
    init_net_ptr = (void *)kallsyms_lookup_name("init_net");

    /* 动态获取 Netlink 相关函数 */
    __nl_create  = (nl_create_t)kallsyms_lookup_name("netlink_kernel_create");
    __nl_release = (nl_release_t)kallsyms_lookup_name("netlink_kernel_release");
    __alloc_skb  = (alloc_skb_t)kallsyms_lookup_name("alloc_skb");
    __kfree_skb  = (kfree_skb_t)kallsyms_lookup_name("kfree_skb");
    __nl_unicast = (nl_unicast_t)kallsyms_lookup_name("nlmsg_unicast");
    __nl_put     = (nl_put_t)kallsyms_lookup_name("nlmsg_put");
    __nl_end     = (nl_end_t)kallsyms_lookup_name("nlmsg_end");

    if (!__nl_create || !__nl_release || !__alloc_skb || !__kfree_skb ||
        !__nl_unicast || !__nl_put || !__nl_end) {
        printk(KERN_ERR "NL_DEMO: missing symbols\n");
        return -1;
    }

    struct netlink_kernel_cfg cfg = { .input = NULL };
    nl_sk = __nl_create(init_net_ptr, NETLINK_TEST, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "NL_DEMO: create failed\n");
        return -1;
    }

    printk(KERN_INFO "NL_DEMO: socket created (proto=%d)\n", NETLINK_TEST);
    return 0;
}

static long exit(void *__user reserved)
{
    if (nl_sk) {
        __nl_release(nl_sk);
        nl_sk = NULL;
    }
    printk(KERN_INFO "NL_DEMO: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);
KPM_CTL0(netlink_control0);