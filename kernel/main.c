#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define REDFINGER_DEV "redfinger"
#define CMD_BASE 0xC0000000
#define REDF_SET_UID  (CMD_BASE + 1)


char *blocked_path_rule[]= {
    "/sys/module/goldfish_audio",
    "/sys/module/goldfish_sync"
};
#define ARRAY_LENGTH(x) (sizeof(x) / sizeof(x[0]))

// sizeof(array_str) / sizeof(array_str[0])

// #  ifdef __i386__
// #  ifdef __x86_64__


// 
bool enabled_anti_detection = false;

#define MAX_APP_UID_COUNT 200

uid_t normal_app_uids[MAX_APP_UID_COUNT] = {0};

uid_t monitor_uid = -1;


static bool add_app_uid(uid_t app_uid) {
    bool added = false;
    int i;
    for (i = 0; i < MAX_APP_UID_COUNT; i++) {
        if (normal_app_uids[i] == 0) {
            normal_app_uids[i] = app_uid;
            added = true;
            break;
        }
    }
    return added;
}

static bool remove_app_uid(uid_t app_uid) {
    bool removed = false;
    int i;
    for (i = 0; i < MAX_APP_UID_COUNT; i++) {
        if (normal_app_uids[i] == app_uid) {
            normal_app_uids[i] = 0;
            removed = true;
            break;
        }
    }
    return removed;
}

static bool exists_app_uid(uid_t app_uid) {
    bool found = false;
    int i;
    for (i = 0; i < MAX_APP_UID_COUNT; i++) {
        if (normal_app_uids[i] == app_uid) {
            found = true;
            break;
        }
    }
    return found;
}


static bool is_block(uid_t uid, const char* pathname) {
    if (!enabled_anti_detection) {
        return false;
    }
    if (uid < 10000) {
        return false;
    }
    bool match = false;
    int i;
    for (i = 0; i < ARRAY_LENGTH(blocked_path_rule); i++) {
        if (!strncmp(pathname, blocked_path_rule[i], strlen(blocked_path_rule[i]))) {
            match = true;
        }
    }
    return match;
}


asmlinkage int jsys_access(const char *pathname, int mode){
    const struct cred *cred = current_cred();

    if(!monitor_uid || (cred->uid.val == monitor_uid)){
        printk(KERN_INFO "[access] pathname %s, mode: %x\n", 
            pathname, mode);
    }
    
    jprobe_return();
    return 0;
}

asmlinkage int jsys_faccessat(int dirfd, const char* pathname, int mode) {
    const struct cred *cred = current_cred();

    if(!monitor_uid || (cred->uid.val == monitor_uid)){
        printk(KERN_INFO "[faccessat] dirfd: %d, pathname %s, mode: %x\n", 
            dirfd, pathname, mode);
    }
    jprobe_return();
    return 0;
}

asmlinkage int jsys_open(const char *pathname, int flags, mode_t mode){
    const struct cred *cred = current_cred();

    if(!monitor_uid || (cred->uid.val == monitor_uid)){
        printk(KERN_INFO "[open] pathname %s, flags: %x, mode: %x\n", 
            pathname, flags, mode);
    }
    
    jprobe_return();
    return 0;
}

asmlinkage int jsys_openat(int dirfd, const char *pathname, int flags, mode_t mode){
    const struct cred *cred = current_cred();

    if(!monitor_uid || (cred->uid.val == monitor_uid)){
        printk(KERN_INFO "[openat] dirfd: %d, pathname %s, flags: %x, mode: %x\n", 
            dirfd, pathname, flags, mode);
    }
    
    jprobe_return();
    return 0;
}

asmlinkage int jdo_sys_open(int dirfd, const char *pathname, int flags, mode_t mode){
    const struct cred *cred = current_cred();

    if(!monitor_uid || (cred->uid.val == monitor_uid)){
        printk(KERN_INFO "[sys_open] dirfd: %d, pathname %s, flags: %x, mode: %x\n", 
            dirfd, pathname, flags, mode);
    }
    jprobe_return();
    return 0;
}

asmlinkage long jsys_ptrace(long request, long pid, unsigned long addr,
               unsigned long data){
    const struct cred *cred = current_cred();
    
    if(!monitor_uid || (cred->uid.val == monitor_uid)){
        switch(request){
            case PTRACE_TRACEME: {
                printk(KERN_INFO "PTRACE_TRACEME: [src]pid = %d\n", current->tgid);            
            }break;
            case PTRACE_PEEKDATA: {
                printk(KERN_INFO "PTRACE_PEEKDATA: [src]pid = %d --> [dst]pid = %d, addr: %lx, data: %lx\n", 
                    current->tgid, pid, addr, data);            
            }break;

            default:{

            }break;
        }
    }
    
    jprobe_return();
    return 0;
}



static struct jprobe ptrace_probe = {
    .entry          = jsys_ptrace,
    .kp = {
        .symbol_name    = "sys_ptrace",
    },
};

static struct jprobe open_probe = {
    .entry          = jsys_open,
    .kp = {
        .symbol_name    = "sys_open",
    },
};

static struct jprobe openat_probe = {
    .entry          = jsys_openat,
    .kp = {
        .symbol_name    = "sys_openat",
    },
};

static struct jprobe do_sys_open_probe = {
    .entry          = jdo_sys_open,
    .kp = {
        .symbol_name    = "do_sys_open",
    },
};

static struct jprobe access_probe = {
    .entry          = jsys_access,
    .kp = {
        .symbol_name    = "sys_access",
    },
};

static struct jprobe faccessat_probe = {
    .entry          = jsys_faccessat,
    .kp = {
        .symbol_name    = "sys_faccessat",
    },
};


static struct jprobe *my_jprobe[] = {
    &open_probe,
    &openat_probe,
    &ptrace_probe,
    &access_probe,
    &faccessat_probe,
    &do_sys_open_probe
};


static int RedfingerHelper_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "RedfingerHelper device open success!\n");
    return 0;
}

static long RedfingerHelper_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
	long ret = 0;
    void __user *argp = (void __user *)arg;
    struct task_struct *target_task;
    struct dump_request *request = (struct dump_request *)argp;
    
    printk(KERN_INFO "Redfinger ioctl cmd[%x], arg[%x]", cmd, arg);
	switch(cmd){
        case REDF_SET_UID:
            monitor_uid = (uid_t) arg;
            printk(KERN_INFO "Set monitor uid: %d\n", monitor_uid);
            break;
        default:
            ret = -EFAULT;
	}
	return ret;
}

static struct file_operations RedfingerHelper_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = RedfingerHelper_unlocked_ioctl,
    .compat_ioctl = RedfingerHelper_unlocked_ioctl,
    .open = RedfingerHelper_open
};

static int major = 0;

struct cdev RedfingerHelper_cdev;
 
static struct class *RedfingerHelper_cls;


static int RedfingerHelper_init(void){
    dev_t dev_id;
    int ret = 0;

    if(major){
        dev_id = MKDEV(major, 0);
        register_chrdev_region(dev_id, 1, REDFINGER_DEV);
    } else {
        alloc_chrdev_region(&dev_id, 0, 1, REDFINGER_DEV);
        major = MAJOR(dev_id);
    }
    cdev_init(&RedfingerHelper_cdev, &RedfingerHelper_fops); 
    cdev_add(&RedfingerHelper_cdev, dev_id, 1);
    RedfingerHelper_cls = class_create(THIS_MODULE, REDFINGER_DEV);
    device_create(RedfingerHelper_cls, NULL, dev_id, NULL, REDFINGER_DEV);

    

    ret = register_jprobes(&my_jprobe, sizeof(my_jprobe) / sizeof(my_jprobe[0]));
    if (ret < 0) {
        printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
        return -1;
    }

    printk(KERN_INFO "Redfinger Helper Init successed\n");
    
    return 0;
}

static void RedfingerHelper_exit(void){
    device_destroy(RedfingerHelper_cls, MKDEV(major, 0));
    class_destroy(RedfingerHelper_cls);
    cdev_del(&RedfingerHelper_cdev);
    unregister_chrdev_region(MKDEV(major, 0), 1);

    unregister_jprobes(&my_jprobe, sizeof(my_jprobe) / sizeof(my_jprobe[0]));
}
 
module_init(RedfingerHelper_init);
module_exit(RedfingerHelper_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frank");
