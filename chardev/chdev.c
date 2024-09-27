#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/fs.h>
#include<linux/slab.h>
#include<linux/timer.h>
#include<linux/sched.h>
#include<linux/list.h>
#include<linux/interrupt.h>

#include<linux/cdev.h> //cdev_init() cdev_add() cdev_del()
#include<linux/types.h> //dev_t
#include<linux/kdev_t.h> //有两个宏获取主设备号和次设备号

#include<linux/uaccess.h> //container_of


dev_t c_devt;  //设备的主次设备号


/*定义一个结构体，包含了cdev,类似与继承，把这个设备文件的属性给继承过来*/
struct char_dev {
    struct cdev c_dev;
    char *c;
    int n;
};


/*设备的操作方法*/
int
char_open(struct inode *inode, struct file *filp)
{
    /*inode->i_cdev是
    cdev_add的第一个参数*/
    struct char_dev *cdev_p = container_of(inode->i_cdev, struct char_dev, c_dev);
    printk("char_open, c_dev%d, %d\n", iminor(inode), MINOR(inode->i_cdev->dev));
    filp->private_data = cdev_p;
    return 0;
}

ssize_t
char_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos)
{
    
    ssize_t ret = 0;
    struct char_dev *cdev_p = filp->private_data;
    printk("char_read, cdev_p = %p\n", cdev_p);
    if(*fpos >= cdev_p->n)
        goto fail;

    if((*fpos + count) > cdev_p->n)
        count = cdev_p->n - *fpos;

    if(copy_to_user(buf, cdev_p->c, count)) {
        ret = -EFAULT;
        goto fail;
    }

    *fpos += count;
    return count;
fail:
    return ret;
}

ssize_t
char_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos)
{
    
    struct char_dev *cdev_p = filp->private_data;
    int ret = -ENOMEM, index = 0;
    printk("char_write, cdev_p = %p, count = %ld\n", cdev_p, count);

    if(cdev_p->c) {
        kfree(cdev_p->c);
        cdev_p->c = NULL;
    }

    cdev_p->n = 0;
 
    cdev_p->c  = kzalloc(count, GFP_KERNEL);
    if(!cdev_p->c) 
        goto fail;
    
    if(copy_from_user(cdev_p->c, buf, count)) {
        ret = -EFAULT;
        goto fail;
    }

    for(index = 0; index < count; index++)
        printk("cdev_p->c[%d] = %c\n", index, cdev_p->c[index]);
    cdev_p->n = count;
    return count;
fail:
    return ret;
}

int
char_release(struct inode *inode, struct file *filp)
{
    printk("char_release\n");
    return 0;
}

struct file_operations char_fops = {
    .owner = THIS_MODULE,
    .read = char_read,
    .write = char_write,
    .open = char_open,
    .release = char_release,
};


struct class *cdev_class;
struct char_dev *cdev_p;

static
int __init hello_init (void)
{
    int ret = 0, index = 0;
    printk("hello_init\n");
    ret = alloc_chrdev_region(&c_devt, 0, 2, "char_dev");
    if(ret)
         printk("alloc_chrdev_region fail\n");

    printk("major = %d, minor = %d\n", MAJOR(c_devt), MINOR(c_devt));

    cdev_p = kzalloc(sizeof(struct char_dev) * 2, GFP_KERNEL);
    if(!cdev_p)
        printk("alloc fail\n");

    for(index = 0; index < 2; index++) {
        cdev_init(&cdev_p[index].c_dev, &char_fops);
        cdev_p[index].c_dev.owner = THIS_MODULE;
        ret = cdev_add(&cdev_p[index].c_dev, 
            MKDEV(MAJOR(c_devt), MINOR(c_devt) + index), 1);
        if(ret) 
            printk("cdev_add fail\n");
    }

    /*根据以下api替代mknod生成设备节点*/
    cdev_class = class_create(THIS_MODULE, "c_dev");
    if(!cdev_class)
        printk("class_create fail\n");

    for(index = 0; index < 2; index++) {
        device_create(cdev_class, NULL, 
            MKDEV(MAJOR(c_devt), MINOR(c_devt) + index), 
            NULL, "c_dev%d", index);
    }
    return ret;
}

static
void __exit hello_exit (void)
{
    int index = 0;
    printk("hello_exit\n");
    for(index = 0; index < 2; index++) {
        device_destroy(cdev_class, 
            MKDEV(MAJOR(c_devt), MINOR(c_devt) + index));
    }

    class_destroy(cdev_class);

    for(index = 0; index < 2; index++) {
         cdev_del(&cdev_p[index].c_dev);
    }

    kfree(cdev_p);

    unregister_chrdev_region(c_devt, 2);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_AUTHOR("Tan xujia");
MODULE_LICENSE("Dual BSD/GPL");