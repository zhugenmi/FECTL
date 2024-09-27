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

#ifndef _FECTL_LSM_H
#define _FECTL_LSM_H

#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/security_ops.h>
#include <linux/fdtable.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

/**
 * 定义的宏
 */
#define FECTL_NAME "security.authorized"
#define FECTL_VALUE_1 "verified"
#define FECTL_VALUE_0 "none"
#define FECTL_VALUE_1_LEN 8
#define FECTL_VALUE_0_LEN 4
#define FECTL_MAX_ATTRLEN 50
#define FECTL_MAX_PATHLEN PAGE_SIZE

char *trash_info_buff = NULL;
char *trash_files_buff = NULL;

/**
 * 函数原型声明
 */
int fectl_check_python_and_others(struct file *file);
int fectl_file_permission(struct file *file, int mask);
int fectl_bprm_check_security(struct linux_binprm *bprm);
int fectl_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);
int fectl_path_chmod(const struct path *path, umode_t mode);

/*以下为公用函数*/
// 检查文件是否有授权标识
static int check_file_authorized(struct file *file) {
    char value[20];
    int ret = vfs_getxattr(d_inode(file->f_path.dentry), FECTL_NAME, value, sizeof(value));
    if (ret < 0 || strcmp(value, FECTL_VALUE_1) != 0) {
        // 未授权
        return -EACCES;
    }
    // 已授权
    return 0;
}

/** 设置文件扩展属性，返回0表示设置成功
 * @dentry: 要设置扩展属性值的文件或目录的目录项
 * @flag: 为1表示信任该文件，为0表示不信任
 */
int fectl_setxattr(struct dentry *dentry, int flag)
{
    int ret;
    if (flag)
        ret = vfs_setxattr(dentry, FECTL_NAME, FECTL_VALUE_1, FECTL_VALUE_1_LEN, 0);
    else
        ret = vfs_setxattr(dentry, FECTL_NAME, FECTL_VALUE_0, FECTL_VALUE_0_LEN, 0);
    return ret;
}

/** 获取文件路径
 * @file: 指向要获取路径名的文件的 struct file 结构体
 * @buf: 指向存储路径名的缓冲区
 * @buflen: 缓冲区的长度
 */
char *file_get_path(struct file *file, char *buf, int buflen)
{
    struct dentry *dentry = file->f_path.dentry;
    char *ret = dentry_path_raw(dentry, buf, buflen);
    return ret;
}

/** 获取文件路径
 * @file: 指向要获取路径名的文件的 struct dentry 结构体
 * @buf: 指向存储路径名的缓冲区
 * @buflen: 缓冲区的长度
 */
char *dentry_get_path(struct dentry *dentry, char *buf, int buflen)
{
    char *ret = dentry_path_raw(dentry, buf, buflen);
    return ret;
}

// 设置文件为未授权标识
static int set_file_unauthorized(struct file *file) {
    return vfs_setxattr(d_inode(file->f_path.dentry), FECTL_NAME, FECTL_VALUE_0, FECTL_VALUE_0_LEN, 0);
}

// 检查并限制脚本文件执行
static int restrict_script_execution(struct linux_binprm *bprm) {
    struct file *file = bprm->file;

    // 获取文件类型
    const char *interpreter = bprm->interp;
    if (interpreter) {
        // 这里可以扩展以检查特定类型的脚本，例如bash, python等
        if (strstr(interpreter, "bash") || strstr(interpreter, "python") || 
            strstr(interpreter, "sh") || strstr(interpreter, "dash")) {
            printk(KERN_INFO "fectl: Script execution attempted: %s\n", interpreter);

            // 检查文件是否被授权
            if (check_file_authorized(file) < 0) {
                printk(KERN_ALERT "fectl: Unauthorized script execution attempted\n");
                return -EACCES; // 拒绝执行未授权的脚本
            }
        }
    }
    return 0;
}

// fectl_file_receive 实现文件接收时的检查
int fectl_file_receive(struct file *file)
{
    printk(KERN_INFO "fectl: call [file_receive]\n");
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

/** 获取当前系统登录的用户名的系统回收站目录
 * @void: 无参
 */
int get_current_trash_path(void)
{
    if (trash_info_buff == NULL)
    {
        struct file *file;
        int i;
        ssize_t bytes_read=0;
        char *current_login_username = NULL;

        file = filp_open("/tmp/user.log", O_RDONLY, 0);
        if (IS_ERR(file))
        {
            printk(KERN_INFO "fectl: Error: Failed to open /tmp/user.log: %ld\n", PTR_ERR(file));
            return -1;
        }

        current_login_username = kmalloc(128, GFP_KERNEL);
        if (unlikely(!current_login_username))
        {
            printk(KERN_WARNING "fectl: Error: Failed to allocate memory dynamically at runtime in kmalloc(). \n");

            return -1;
        }

        trash_info_buff = kmalloc(256, GFP_KERNEL);
        if (unlikely(!trash_info_buff))
        {
            printk(KERN_WARNING "fectl: error: Failed to allocate memory dynamically at runtime in kmalloc(). \n");
            kfree(current_login_username);
            return -1;
        }

        trash_files_buff = kmalloc(256, GFP_KERNEL);
        if (unlikely(!trash_files_buff))
        {
            printk(KERN_WARNING "fectl: error: Failed to allocate memory dynamically at runtime in kmalloc(). \n");
            kfree(current_login_username);
            kfree(trash_info_buff);
            return -1;
        }

        bytes_read = kernel_read(file, current_login_username, sizeof(current_login_username)-1, &file->f_pos);
        if (bytes_read > 0)
        {
            for (i = 0; i < bytes_read; ++i)
            {
                if (current_login_username[i] == ' ' || current_login_username[i] == '\n' || current_login_username[i] == '\r')
                {
                    current_login_username[i] = 0;
                }
            }
            current_login_username[bytes_read - 1] = '\0';
        }else{
            printk(KERN_INFO "fectl: Error: Failed to read /tmp/user.log: %ld\n", PTR_ERR(file));
            kfree(current_login_username);
            kfree(trash_info_buff);
            kfree(trash_files_buff);
            return -1;
        }

        sprintf(trash_info_buff, "/home/%s/.local/share/Trash/info", current_login_username);
        sprintf(trash_files_buff, "/home/%s/.local/share/Trash/files", current_login_username);

        printk(KERN_INFO "fectl: get_current_trash_path() init.\n");
        filp_close(file, NULL);
    }
    return 0;
}

/** 控制python和sh脚本执行，挂在在fectl_file_permission函数中
 * @file: 指向要获取路径名的文件的 struct dentry 结构体
 */
int fectl_check_python_and_others(struct file *file)
{
    if (strcmp(current->comm, "python") == 0 || strcmp(current->comm, "bash") == 0 || strcmp(current->comm, "sh") == 0 || strcmp(current->comm, "dash") == 0 || strcmp(current->comm, "cat") == 0 || strcmp(current->comm, "less") == 0 || strcmp(current->comm, "head") == 0 || strcmp(current->comm, "tail") == 0 || strcmp(current->comm, "grep") == 0 || strcmp(current->comm, "awk") == 0 || strcmp(current->comm, "sed") == 0 || strcmp(current->comm, "cut") == 0 || strcmp(current->comm, "paste") == 0)
    {
        // 如果用户使用了重定向符号，拒绝该操作并返回错误信息
        struct files_struct *files = current->files;
        // 遍历进程的所有文件
        int fd;
        struct file *f;
        struct fdtable *fdt = files_fdtable(files);
        for (fd = 0; fd < fdt->max_fds; fd++)
        {
            // 获取指向文件对象的结构体指针
            f = fcheck_files(files, fd);
            if (f)
            {
                struct dentry *dentry = f->f_path.dentry;
                // 下列代码主要是为了避免fectl与麒麟内部安全策略冲突
                // // 麒麟系统自带扩展属性的大小
                // int size2 = 0;
                // char att2[FECTL_MAX_ATTRLEN];
                // // 获取麒麟系统自带扩展属性
                // size2 = vfs_getxattr(dentry, "security.kysec", att2, FECTL_MAX_ATTRLEN);
                // att2[size2] = '\0';
                // if (strcmp(att2, "none:none:unknown") == 0)
                //     return 0;
                // // 如果该文件还未被麒麟安全策略允许执行则使用麒麟安全策略拦截，否则使用fectl策略拦截
                int size = 0;
                char att[FECTL_MAX_ATTRLEN];
                // 获取扩展属性
                size = vfs_getxattr(dentry,FECTL_NAME, att, FECTL_MAX_ATTRLEN);
                if (size >= 0)
                    att[size] = '\0';
                else
                    att[0] = '\0';
                // printk("%s+%s+%s+%d",current->comm,dentry->d_name.name,att,size);
                if (size > 0 && strcmp(att, "none") == 0)
                {
                    printk(KERN_WARNING "fectl: call [check_python_and_others] for the file %s,the command of '%s %s' has been denyed!\n", dentry->d_name.name, current->comm, dentry->d_name.name);
                    return -EACCES;
                }
            }
        }

        if (strcmp(current->comm, "python") == 0 || strcmp(current->comm, "bash") == 0 || strcmp(current->comm, "sh") == 0 || strcmp(current->comm, "dash") == 0 || strcmp(current->comm, "cat") == 0 || strcmp(current->comm, "less") == 0 || strcmp(current->comm, "head") == 0 || strcmp(current->comm, "tail") == 0 || strcmp(current->comm, "grep") == 0 || strcmp(current->comm, "awk") == 0 || strcmp(current->comm, "sed") == 0 || strcmp(current->comm, "cut") == 0 || strcmp(current->comm, "paste") == 0)
        {
            int size = 0;
            char att[FECTL_MAX_ATTRLEN];
            // 获取扩展属性
            size = vfs_getxattr(file->f_path.dentry, FECTL_NAME, att,FECTL_MAX_ATTRLEN);
            if (size >= 0)
                att[size] = '\0';
            else
                att[0] = '\0';
            // printk("%s+%s",file->f_path.dentry->d_name.name,att);
            if (strcmp(att, "none") == 0)
            {
                printk(KERN_WARNING "fectl: call [check_python_and_others] for the file %s,the command of '%s %s' has been denyed!\n", file->f_path.dentry->d_name.name, current->comm, file->f_path.dentry->d_name.name);
                return -EACCES;
            }
        }
    }

    return 0;
}

/** 检查文件的访问权限并设置文件的扩展属性，如果是写文件就将其标记为none
 * @file: 文件对象指针
 * @mask: 访问掩码，表示要检查的访问权限类型
 * @return: 返回值为 0，表示函数执行成功。
 */
int fectl_file_permission(struct file *file, int mask)
{
    struct dentry *dentry = file->f_path.dentry;
    struct inode *inode = d_backing_inode(dentry);
    char att[FECTL_MAX_ATTRLEN];
    int mod = inode->i_mode;
    int size = 0;
    char *path_buff;
    char *path = NULL;

    if (fectl_check_python_and_others(file) != 0)
        return -EACCES;

    size = __vfs_getxattr(dentry, inode, FECTL_NAME, att, FECTL_MAX_ATTRLEN);

    if ((mod & 0xf000) != 0x8000)
    {
        return 0;
    }

    path_buff = kmalloc(FECTL_MAX_PATHLEN, GFP_KERNEL);
    if (unlikely(!path_buff))
    {
        printk(KERN_WARNING "fectl: error: Failed to allocate memory dynamically at runtime in kmalloc().\n");
        return 0;
    }

    memset(path_buff, 0, FECTL_MAX_PATHLEN);
    path = file_get_path(file, path_buff, FECTL_MAX_PATHLEN);

    if (path == NULL)
    {
        printk(KERN_WARNING "fectl: error: Failed to get path in file_get_path(). \n");
        kfree(path_buff);
        return 0;
    }

    if (mask & MAY_WRITE)
    {
        if (size <= 0)
        {
            // printk(KERN_INFO "fectl: call [file_permission] of %s use %d, by pid: %d, mod: %x, no such xatt, set it none\n", path, mask, get_current()->pid, mod); // no such xattr
            fectl_setxattr(dentry, 0);
        }
        else if (strcmp(att, "verified") == 0)
        {
            // printk(KERN_INFO "fectl: call [file_permission] of %s use %d, by pid: %d, mod: %x, set it none\n", path, mask, get_current()->pid, mod);
            fectl_setxattr(dentry, 0);
        }
    }
    kfree(path_buff); // 释放内存
    return 0;
}

/** 执行可执行文件时检查其安全性。
 * 若当前用户为root，则不检查直接返回0.否则：
 * 仅当该程序存在扩展标记security.authorized,且其值为verified时才允许其执行，否则返回错误码禁止其执行
 * @bprm: 待执行的可执行文件
 * @return: 返回值为 0，表示函数执行成功。
 */
int fectl_bprm_check_security(struct linux_binprm *bprm)
{
    struct task_struct *task = current;
    kuid_t uid = task->cred->uid;

    struct dentry *dentry = bprm->file->f_path.dentry;

    int size = 0;
    char att[FECTL_MAX_ATTRLEN];

    // 获取扩展属性
    size = vfs_getxattr(dentry, FECTL_NAME, att, FECTL_MAX_ATTRLEN);
    if (size > 0)
    {
        if (strcmp(att, "verified") == 0)
        {
            // printk(KERN_INFO "fectl: call [bprm_check_security] of %s with %s allowing access for UID %d\n", bprm->filename, att, uid.val);
            return 0;
        }
        else
        {
            printk(KERN_INFO "fectl: call [bprm_check_security] of %s with %s deny access for UID %d\n", bprm->filename, att, uid.val);
            return -EPERM;
        }
    }
    printk(KERN_INFO "fectl: call [bprm_check_security] of %s  no xattr found for UID %d \n", bprm->filename, uid.val);
    return -EPERM;
}

/** 将一个文件或目录重命名为另一个文件或目录时，其将被标识成未授权none；涉及到回收站的文件不做处理
 * @old_dir: 旧文件或目录所在的目录的inode结构体指针
 * @old_dentry: 旧文件或目录的dentry结构体指针
 * @new_dir: 新文件或目录所在的目录的inode结构体指针
 * @new_dentry: 新文件或目录的dentry结构体指针
 */
int fectl_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    // 扩展属性的大小
    int size = 0;
    char att[FECTL_MAX_ATTRLEN];
    char *path_old = NULL;
    char *path_new = NULL;
    char *path_old_parent = NULL;
    char *path_new_parent = NULL;
    char *path_buff_new;
    char *path_buff_old;
    char *path_buff_old_parent;
    char *path_buff_new_parent;

    struct dentry *old_parent_dentry = old_dentry->d_parent;
    struct dentry *new_parent_dentry = new_dentry->d_parent;

    path_buff_old_parent = kmalloc(FECTL_MAX_PATHLEN, GFP_KERNEL);
    if (unlikely(!path_buff_old_parent))
    {
        printk(KERN_WARNING "[fectl] error: Failed to allocate memory dynamically at runtime in kmalloc(). \n");
        kfree(path_buff_old_parent);
        return 0;
    }

    path_buff_new_parent = kmalloc(FECTL_MAX_PATHLEN, GFP_KERNEL);
    if (unlikely(!path_buff_new_parent))
    {
        printk(KERN_WARNING "[fectl] error: Failed to allocate memory dynamically at runtime in kmalloc(). \n");
        kfree(path_buff_new_parent);
        return 0;
    }

    memset(path_buff_old_parent, 0, FECTL_MAX_PATHLEN);
    path_old_parent = dentry_get_path(old_parent_dentry, path_buff_old_parent, FECTL_MAX_PATHLEN);
    if (path_old_parent == NULL)
    {
        printk(KERN_WARNING "[fectl] error: Failed to get path in dentry_get_path(). \n");
        kfree(path_buff_old_parent);
        return 0;
    }

    memset(path_buff_new_parent, 0, FECTL_MAX_PATHLEN);
    path_new_parent = dentry_get_path(new_parent_dentry, path_buff_new_parent, FECTL_MAX_PATHLEN);
    if (path_new_parent == NULL)
    {
        printk(KERN_WARNING "[fectl] error: Failed to get path in dentry_get_path(). \n");
        kfree(path_buff_new_parent);
        return 0;
    }

    if(get_current_trash_path()==0){
            if (strcmp(path_old_parent, trash_info_buff) == 0  ||
                strcmp(path_old_parent, trash_files_buff) == 0 ||
                strcmp(path_new_parent, trash_info_buff) == 0  ||
                strcmp(path_new_parent, trash_files_buff) == 0)
        {
            printk(KERN_INFO "[fectl] call [inode_rename] Trash_bin-related files: file moving related to the Trash bin, filename: %s -> %s\n", old_dentry->d_iname, new_dentry->d_iname);
            printk(KERN_INFO "[fectl] call [inode_rename] Trash_bin-related files: path of its old_parent: %s\n", path_old_parent);
            printk(KERN_INFO "[fectl] call [inode_rename] Trash_bin-related files: path of its new_parent: %s\n", path_new_parent);
            return 0;
        }
    }


    path_buff_new = kmalloc(FECTL_MAX_PATHLEN, GFP_KERNEL);
    if (unlikely(!path_buff_new))
    {
        printk(KERN_WARNING "[fectl] error: Failed to allocate memory dynamically at runtime in kmalloc(). \n");
        return 0;
    }
    path_buff_old = kmalloc(FECTL_MAX_PATHLEN, GFP_KERNEL);
    if (unlikely(!path_buff_old))
    {
        printk(KERN_WARNING "[fectl] error: Failed to allocate memory dynamically at runtime in kmalloc(). \n");
        kfree(path_buff_new);
        return 0;
    }
    memset(path_buff_old, 0, FECTL_MAX_PATHLEN);
    path_old = dentry_get_path(old_dentry, path_buff_old, FECTL_MAX_PATHLEN);

    if (path_old == NULL)
    {
        printk(KERN_WARNING "[fectl] error: Failed to get path in dentry_get_path(). \n");
        kfree(path_buff_new);
        kfree(path_buff_old);
        return 0;
    }

    memset(path_buff_new, 0, FECTL_MAX_PATHLEN);
    path_new = dentry_get_path(new_dentry, path_buff_new, FECTL_MAX_PATHLEN);

    if (path_new == NULL)
    {
        printk(KERN_WARNING "[fectl] error: Failed to get path in dentry_get_path(). \n");
        kfree(path_buff_new);
        kfree(path_buff_old);
        return 0;
    }
    // printk(KERN_INFO "[fectl] call [inode_rename] rename %s to %s, set the new file as none\n", path_old, path_new);


    // 获取扩展属性
    size = vfs_getxattr(old_dentry, FECTL_NAME, att, FECTL_MAX_ATTRLEN);
    if (size > 0)
    {
        printk(KERN_INFO "[fectl] call [inode_rename] %s: its xattr will be modified.\n", path_new);
        __vfs_setxattr(old_dentry, d_backing_inode(old_dentry), FECTL_NAME, FECTL_VALUE_0, FECTL_VALUE_0_LEN, XATTR_REPLACE);
        kfree(path_buff_new);
        kfree(path_buff_old);
        return 0;
    }
    // 没有扩展属性，标记为未授权none
    printk(KERN_INFO "[fectl] call [inode_rename] %s: no xattr found, set it as none\n", path_new);
    __vfs_setxattr(old_dentry, d_backing_inode(old_dentry), FECTL_NAME, FECTL_VALUE_0, FECTL_VALUE_0_LEN, XATTR_CREATE);

    kfree(path_buff_old);
    kfree(path_buff_new);
    return 0;
}

/** 文件权限发生改变时其安全状态将发生改变
 * @path: 更改权限的文件或目录的路径
 * @umode_t: 文件权限值
 */
int fectl_path_chmod(const struct path *path, umode_t mode)
{
    struct dentry *ddentry = path->dentry;
    int attr_size = 0;
    char att[FECTL_MAX_ATTRLEN];

    attr_size = vfs_getxattr(ddentry, FECTL_NAME, att, FECTL_MAX_ATTRLEN);

    if (attr_size > 0)
    {
        printk(KERN_INFO "fectl: call [path_chmod] %s: file's mode has changed, its xattr will be modified.\n", ddentry->d_name.name);

        // 修改扩展属性为不可信
        __vfs_setxattr(ddentry, d_backing_inode(ddentry), FECTL_NAME, FECTL_VALUE_0, FECTL_VALUE_0_LEN, 0x2);

        return 0;
    }

    printk(KERN_INFO "fectl: call [path_chmod] %s: file's mode has changed, set the xattr as none.\n", ddentry->d_name.name);

    // 没有扩展属性，标记为未授权none
    __vfs_setxattr(ddentry, d_backing_inode(ddentry), FECTL_NAME, FECTL_VALUE_0, FECTL_VALUE_0_LEN, 0x1);

    return 0;
}

#endif /*_FECTL_LSM_H*/