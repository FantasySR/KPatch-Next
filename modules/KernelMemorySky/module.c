#include <linux/kernel.h>
#include <linux/printk.h>

KPM_NAME("KernelMemorySky");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FantasySR");
KPM_DESCRIPTION("Interceptor test with KPatch Next");

static long init(const char *args, const char *event, void __user *reserved) {
    printk(KERN_INFO "KernelMemorySky: loaded\n");
    return 0;
}

static long exit(void __user *reserved) {
    printk(KERN_INFO "KernelMemorySky: unloaded\n");
    return 0;
}

KPM_INIT(init);
KPM_EXIT(exit);