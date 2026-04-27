/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * 参数传递测试模块 - 仅验证 KPM_CTL0 调参功能
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("ParameterTest");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Test KPM parameter passing via CTL0");

/*
 * 控制函数：当您在 SukiSU Ultra 里点击“调参”并输入参数后，
 * 内核会调用这个函数，args 就是您输入的字符串。
 */
static long param_control0(const char *args, char *__user out_msg, int outlen)
{
    // 安全地记录收到的参数（绝不会死机）
    printk(KERN_INFO "KMS_PARAM_TEST: control0 called, args = [%s]\n",
           args ? args : "(null)");

    // 尝试返回信息给 App（如果 App 支持显示返回值）
    if (out_msg && outlen > 0) {
        // 使用内核提供的安全拷贝函数，避免依赖 copy_to_user
        strncpy(out_msg, "ok, param received", outlen);
    }

    return 0; // 返回 0 表示成功
}

static long init(const char *args, const char *event, void *__user reserved)
{
    printk(KERN_INFO "KMS_PARAM_TEST: module loaded (ready for parameter test)\n");
    return 0;
}

static long exit(void *__user reserved)
{
    printk(KERN_INFO "KMS_PARAM_TEST: module unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);
KPM_CTL0(param_control0);