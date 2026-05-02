/* 基于已验证的 sendto 钩子，直接从数据中提取 HTTP 请求头 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("2.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Http Request Monitor");

static int monitor_running = 0;

static void analyze_http_request(const char *data, int len) {
    // 只处理以 GET 或 POST 开头的数据包
    if (len < 4) return;
    if (!(data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') &&
        !(data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T')) {
        return;
    }

    // 临时缓冲区用于安全拷贝和字符串操作
    char buf[512];
    int copy_len = len < sizeof(buf)-1 ? len : sizeof(buf)-1;
    memcpy(buf, data, copy_len);
    buf[copy_len] = '\0';

    // 提取请求行
    char *line_end = strchr(buf, '\r');
    if (line_end) *line_end = '\0';
    printk(KERN_INFO "KMS_NET| REQUEST: %s\n", buf);

    // 查找 Host: 头
    char *host_start = strstr(buf, "Host: ");
    if (host_start) {
        host_start += 6; // 跳过 "Host: "
        char *host_end = strchr(host_start, '\r');
        if (host_end) *host_end = '\0';
        printk(KERN_INFO "KMS_NET| URL: %s%s\n", host_start, buf + 4); // 组合 Host + 路径
    }
}

static void before_sendto(hook_fargs6_t *fargs, void *udata) {
    if (!monitor_running) return;
    
    // 获取用户态缓冲区指针和长度
    const char __user *buf = (const char __user *)syscall_argn(fargs, 1);
    size_t len = (size_t)syscall_argn(fargs, 2);
    
    if (!buf || len == 0) return;
    
    // 安全地从用户空间拷贝数据
    char tmp[512];
    int copy_len = len < sizeof(tmp) ? len : sizeof(tmp);
    if (compat_strncpy_from_user(tmp, buf, copy_len) > 0) {
        analyze_http_request(tmp, copy_len);
    }
}

// ... (CTL0控制、init/exit 函数保持不变，省略以节省篇幅)