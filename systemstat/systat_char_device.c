#include<linux/module.h>
#include<linux/fs.h>
#include<linux/cdev.h>
#include<linux/slab.h>

// 主从设备号、设备个数
#define SYSTAT_MAJOR 0
#define SYSTAT_MINOR 0
#define SYSTAT_NUM_DEVS 1

int systat_major=SYSTAT_MAJOR;
int systat_minor=SYSTAT_MINOR;
int systat_num_devs=SYSTAT_NUM_DEVS;

// 将主设备号和从设备号结合：高12位为主设备号，低20位为从设备号
dev_t devt;

//利用模块参数的方式，将设备号和设备个数作为模块参数，方便在加载模块时动态调整参数值
module_param(systat_major,int,S_IRUGO);
module_param(systat_minor,int,S_IRUGO);
module_param(systat_num_devs,int,S_IRUGO);

// 实际的字符设备结构
struct systat_char_dev{
    struct cdev cdev;
    char *c; 
    int n;
};

struct systat_char_dev* sc_devp;

int sc_open(struct inode*inode,struct file*filp){
    // printk(KERN_INFO "open systat_chr%d %d\n",iminor(inode),MINOR(inode->i_cdev->dev));
    struct systat_char_dev *cdev_p = container_of(inode->i_cdev, struct systat_char_dev, cdev);
    printk("char_open, cdev%d, %d\n", iminor(inode), MINOR(inode->i_cdev->dev));
    filp->private_data = cdev_p;
    return 0;
}

ssize_t sc_read(struct file*filp,char __user*buf,size_t count,loff_t*fpos){
    ssize_t ret = 0;
    struct systat_char_dev *cdev_p = filp->private_data;
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

ssize_t sc_write(struct file*filp,const char __user*buf,size_t count,loff_t*f_ops){
    struct systat_char_dev *cdev_p = filp->private_data;
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

int sc_release(struct inode*inode,struct file*filp){
    printk(KERN_INFO "release systat_chr\n");
    return 0;
}

// 字符设备的操作函数
struct file_operations sc_fops={
    .owner=THIS_MODULE,
    .read=sc_read,
    .write=sc_write,
    .open=sc_open,
    .release=sc_release,
};

static int __init systat_init(void){
    int ret=0,i=0;
    printk(KERN_INFO "----BEGIN SYSTAT LINUX MODULE----\n");

    //若主设备不为0，则手动分配
    if(systat_major){
        devt=MKDEV(systat_major,systat_minor);
        ret=register_chrdev_region(devt,systat_num_devs,"systat_chr"); //使用指定的设备号分配
    }
    else{
        ret=alloc_chrdev_region(&devt,systat_minor,systat_num_devs,"systat_chr"); //动态分配主设备号
        systat_major=MAJOR(devt);
    }

    if(ret<0){
        printk(KERN_WARNING "systat: can't get major %d\n",systat_major);
        goto fail;
    }
    else{
        ;
    }

    sc_devp=kzalloc(sizeof(struct systat_char_dev)*systat_num_devs,GFP_KERNEL);// 给字符设备分配空间

    if(!sc_devp){
        printk(KERN_WARNING "memory alloc fail.\n");
        ret=-ENOMEM;
        goto failure_kzalloc;
    }
    else{
        ;
    }

    for(i=0;i<systat_num_devs;i++){
        cdev_init(&sc_devp[i].cdev,&sc_fops); //初始化字符设备结构
        sc_devp[i].cdev.owner=THIS_MODULE;
        ret=cdev_add(&sc_devp[i].cdev,MKDEV(systat_major,systat_minor+1),1); //添加至内核

        if(ret){
            printk(KERN_WARNING "fail add sc_dev%d",i);
        }
    }
    return 0;

failure_kzalloc:
    unregister_chrdev_region(devt,systat_num_devs);
fail:
    return ret;
}

static void __exit systat_exit(void){
    int i=0;

    for(i=0;i<systat_num_devs;i++){
        cdev_del(&sc_devp[i].cdev);
    }
    kfree(sc_devp);
    unregister_chrdev_region(devt,systat_num_devs); //移除模块时释放设备号
    printk(KERN_INFO "systat unregistered.\n");
    printk(KERN_INFO "----END SYSTAT LINUX MODULE----\n");
}

module_init(systat_init);
module_exit(systat_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("LJJ");
MODULE_VERSION("V1.0");