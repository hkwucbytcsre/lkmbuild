/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SITA_DDK_LKM_H
#define _SITA_DDK_LKM_H
/*
 * sita_ddk_lkm.h —— 模块内部头文件
 * 声明 sita_ddk.c（原工程改名而来）提供给 sita_kprobe_main.c 的所有符号。
 * sita_ddk.c 里的 #include <linux/xingguang_ddk.h> 要换成 #include "sita_ddk_lkm.h"。
 */
#include <linux/types.h>

struct block_device; struct file; struct iov_iter; struct kiocb;
struct linux_binprm; struct vm_area_struct; struct task_struct;
enum kernel_read_file_id; enum kernel_load_data_id;

/* —— callsite 逻辑（原 9 个，定义在 sita_ddk.c） —— */
int  sita_ddk_vfs_write(struct file *file, const char __user *buf,
			size_t count, loff_t *pos);
int  sita_ddk_vfs_iter_write(struct file *file, struct iov_iter *iter,
			     loff_t *pos);
int  sita_ddk_blkdev_write_iter(struct kiocb *iocb, struct iov_iter *iter);
int  sita_ddk_blkdev_ioctl(struct block_device *bdev, unsigned int cmd);
int  sita_ddk_blkdev_fallocate(struct file *file, int mode,
			       loff_t start, loff_t len);
int  sita_ddk_blkdev_mmap(struct file *file, struct vm_area_struct *vma);
int  sita_ddk_blkdev_issue_discard(struct block_device *bdev,
				   sector_t sector, sector_t nr_sects);
int  sita_ddk_blkdev_issue_zeroout(struct block_device *bdev,
				   sector_t sector, sector_t nr_sects);
void sita_ddk_dm_target_add(const char *type);

/* —— LSM hook 判定函数（在 sita_ddk.c 中必须去掉 static！） —— */
int sita_bprm_check_security(struct linux_binprm *bprm);
int sita_file_open(struct file *file);
int sita_file_permission(struct file *file, int mask);
int sita_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int sita_mmap_file(struct file *file, unsigned long reqprot,
		   unsigned long prot, unsigned long flags);
int sita_file_mprotect(struct vm_area_struct *vma,
		       unsigned long reqprot, unsigned long prot);
int sita_ptrace_access_check(struct task_struct *child, unsigned int mode);
int sita_ptrace_traceme(struct task_struct *parent);
int sita_kernel_read_file(struct file *file, enum kernel_read_file_id id,
			  bool contents);
int sita_kernel_load_data(enum kernel_load_data_id id, bool contents);

/* —— 模块内辅助（sita_ddk.c 末尾改造提供） —— */
int  sita_watchdog_start_lkm(void);   /* 原 late_initcall(sita_watchdog_start) */
int  sita_stage_arm_late_lkm(void);   /* 原 late_initcall(sita_stage_arm_late) */
void sita_ddk_lkm_hook_enter(void);   /* __module_get(THIS_MODULE) */

#endif /* _SITA_DDK_LKM_H */
