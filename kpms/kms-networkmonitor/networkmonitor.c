#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>

KPM_NAME("KMS_NetMonitor");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Minimal load test for netmon");

static long init(const char *args, const char *event, void *__user reserved) {
    printk(KERN_INFO "KMS_NET: minimal module loaded\n");
    return 0;
}

static long exit(void *__user reserved) {
    printk(KERN_INFO "KMS_NET: minimal module unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);