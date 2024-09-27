// SPDX-License-Identifier: GPL-3.0-only
/*
 *  FECTL-Execution Control Based on File Extended Attributes
 *
 *  Copyright (C) 2024 zhugenmi  <zhugenmi@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/xattr.h>
#include <linux/types.h>
#include <linux/fdtable.h>
#include <linux/binfmts.h>
#include <linux/string_helpers.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include<linux/path.h>
#include<linux/namei.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include "fectl_lsm.h"

int fectl_inode_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags) 
{
    struct task_struct *task=current;	//get_curent
    kuid_t uid=task->cred->uid;
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;

    char att[100];
    int len=99 <size? 99 : size;
    if (unlikely(!path_buff))
    {
    	printk(KERN_NOTICE  "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
        kfree(path_buff);
    	printk(KERN_NOTICE  "Calling get_path failed!\n");
    	return 0;
    }
    
    strncpy(att, value, len);
    att[len]='\0';
    printk(KERN_INFO "[fectl: inode_setxattr] of %s by pid: %d.\n", path, task->pid);
	printk(KERN_INFO "And name of this xattr is %s with value %s.lenth is %ld and flags is %d.\n", name, att, size, flags);
    kfree(path_buff);	
	// The role of the above section is to output information
	if(uid.val != 0 && !strcmp(name, FECTL_NAME)) {
		printk(KERN_INFO "Modify incorrect xattributes under non-root privileges!!!\n");
		return -1;   
	}
	return 0;
	
}


int fectl_inode_removexattr(struct dentry *dentry, const char *name) 
{
    struct task_struct *task=current;	//get_curent
    kuid_t uid=task->cred->uid;
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;

    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
        kfree(path_buff);
    	printk(KERN_INFO "Calling get_path failed!\n");
    	return 0;
    }
    printk(KERN_INFO "[fectl: inode_removexattr] of %s by pid: %d.\n", path, task->pid);
	printk(KERN_INFO "And name of this xattr is %s.\n", name);
    kfree(path_buff);	//free is necessary and very important
	// The role of the above section is to output information
	if(uid.val != 0 && !strcmp(name, FECTL_NAME)) {
		printk(KERN_INFO "Remove incorrect xattributes under non-root privileges!!!\n");
		return -1;   
    }
	return 0;
}


int fectl_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct task_struct *task=current;	//get_curent
    kuid_t uid=task->cred->uid;
    char *path_buff;
    char *path = NULL;
    //Root can access everything.
    if(uid.val==0)
    {
	    return 0;
    } 
    
    path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	
        printk(KERN_INFO "Calling get_path failed!\n");
    	kfree(path_buff);
        return 0;
    }
    
    
    printk(KERN_INFO "[fectl: call inode_create of %s by pid: %d, mod : %x\n", path, task->pid, mode);
    printk("start, ns:%p, dentry:%p, inode:%p.\n", task->real_cred->user_ns, dentry, dentry->d_inode);
    kfree(path_buff);	//free

    return 0;
}


int fectl_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;
    char *new_path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *new_path = NULL;
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(old_dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!\n");
        kfree(path_buff);	//free
        kfree(new_path_buff);
        return 0;
    }
    
    if (unlikely(!new_path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(new_path_buff, 0, PAGE_SIZE);
    new_path = dentry_get_path(new_dentry, new_path_buff, PAGE_SIZE);
    
    if (new_path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!\n");
        kfree(path_buff);	//free
        kfree(new_path_buff);
        return 0;
    }

    kfree(path_buff);	//free
    kfree(new_path_buff);	//free
    return 0;
}


int fectl_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!\n");
    	kfree(path_buff);
        return 0;
    }

    kfree(path_buff);	//free
    return 0;
}


int fectl_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)
{
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!\n");
    	kfree(path_buff);
        return 0;
    }
    kfree(path_buff);	//free
    return 0;
}


int fectl_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!\n");
    	kfree(path_buff);
        return 0;
    }

    kfree(path_buff);	//free
    return 0;
}


int fectl_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "path_buff failed for path_buff.\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!\n");
    	kfree(path_buff);
        return 0;
    }

    kfree(path_buff);	//free
    return 0;
}


int fectl_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
    char *path_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
    char *path = NULL;
    if (unlikely(!path_buff))
    {
    	printk(KERN_INFO "Kmalloc failed for path_buff\n");
    	return 0;
    }
    memset(path_buff, 0, PAGE_SIZE);
    path = dentry_get_path(dentry, path_buff, PAGE_SIZE);
    
    if (path == NULL)
    {
    	printk(KERN_INFO "Calling get_path failed!\n");
    	kfree(path_buff);
        return 0;
    }

    kfree(path_buff);	//free
    return 0;
}


// fectl_file_receive 实现文件接收时的检查
int fectl_file_receive(struct file *file)
{
    printk(KERN_INFO "fectl: call [file_receive]\n");
    // printk(KERN_INFO "fectl: call [file_receive]\n");
    return check_file_authorized(file);
}

// fectl_task_to_inode 实现任务到inode的映射
void fectl_task_to_inode(struct task_struct *p, struct inode *inode)
{
    printk(KERN_INFO "fectl: call [task_to_inode]\n");

    if (inode && S_ISREG(inode->i_mode)) {
        struct file *file = fget(p->files->fd);
        if (file) {
            if (check_file_authorized(file) < 0) {
                printk(KERN_ALERT "fectl: Unauthorized file access attempted\n");
                // 处理未授权访问的逻辑，例如终止任务等
            }
            fput(file);
        }
    }
}

// 监视新创建、下载和拷贝的文件
static int fectl_inode_post_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
    struct file *file = dentry_open(dentry, O_RDONLY, current_cred());
    if (!IS_ERR(file)) {
        set_file_unauthorized(file);
        fput(file);
    }
    return 0;
}

// 监视文件修改、重命名、移动和权限变化
static int fectl_inode_permission(struct inode *inode, int mask) {
    if ((mask & MAY_WRITE) || (mask & MAY_EXEC)) {
        struct dentry *dentry = d_find_alias(inode);
        if (dentry) {
            struct file *file = dentry_open(dentry, O_RDONLY, current_cred());
            if (!IS_ERR(file)) {
                set_file_unauthorized(file);
                fput(file);
            }
            dput(dentry);
        }
    }
    return 0;
}

static struct security_operations fectl_ops = {
    .name = "fectl_lsm",

    .file_permission = fectl_file_permission,
    .file_receive = fectl_file_receive,

    .inode_setxattr=fectl_inode_setxattr,
    .inode_removexattr=fectl_inode_removexattr,
    .inode_create = fectl_inode_create,
    .inode_rename = fectl_inode_rename,
      
    .inode_link=fectl_inode_link,
    .inode_unlink = fectl_inode_unlink,
    .inode_symlink=fectl_inode_symlink,
    .inode_mkdir=fectl_inode_mkdir,
    .inode_rmdir=fectl_inode_rmdir,
    .inode_mknod=fectl_inode_mknod,

    .bprm_check_security = fectl_bprm_check_security,
    .path_chmod = fectl_path_chmod

    .task_to_inode=fectl_task_to_inode
    };

static int fectl_init(void)
{
    int ret;

    ret = security_add_external_ops(&fectl_ops);
    if (ret < 0)
        return ret;

    printk(KERN_INFO "fectl: Module loaded successfully.\n");

        return 0;
}

static void fectl_exit(void)
{
    security_del_external_ops(&fectl_ops);
    printk(KERN_INFO "fectl: Module unloaded!\n");
}

module_init(fectl_init);
module_exit(fectl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhugenmi");
MODULE_DESCRIPTION("Execution Control Based on File Extended Attribute");