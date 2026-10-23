// SPDX-License-Identifier: GPL-2.0
/*
 * sita_kprobe_main.c —— 针对 Linux 6.6 GKI（arm64）的全 kprobe 模块壳
 *
 * 前置：同目录必须有改名后的 sita_ddk.c / kernel_compat.h / sita_ddk_lkm.h
 * （见 README 第 5 节 sed 改名 + 本节"必改三处"）。
 *
 * 参数映射均按原 callsite 补丁（0010/0020/0021/0030/0040）核对：
 *  - vfs_write(file, buf, count, pos)                  -> sita_ddk_vfs_write(file, buf, count, &pos)
 *  - vfs_iter_write(file, iter, pos, flags)          -> sita_ddk_vfs_iter_write(file, iter, pos)  [arg2 已是指针]
 *  - vfs_iocb_iter_write(iocb, iter)                 -> sita_ddk_vfs_iter_write(iocb->ki_filp, iter, &iocb->ki_pos)
 *  - blkdev_write_iter(iocb, from)                   -> sita_ddk_blkdev_write_iter(iocb, from)
 *  - blkdev_fallocate(file, mode, start, len)        -> sita_ddk_blkdev_fallocate(file, mode, start, len)
 *  - blkdev_mmap(file, vma)                          -> sita_ddk_blkdev_mmap(file, vma)
 *  - blkdev_ioctl(file, cmd, arg)                    -> sita_ddk_blkdev_ioctl(I_BDEV(file_inode(file)), cmd)  [注意:2 参]
 *  - __blkdev_issue_discard(bdev, sector, nr, gfp)     -> sita_ddk_blkdev_issue_discard(bdev, sector, nr)       [注意:3 参]
 *  - __blkdev_issue_zeroout(bdev, sector, nr, ...)     -> sita_ddk_blkdev_issue_zeroout(bdev, sector, nr)        [注意:3 参]
 *  - dm_table_add_target(t, type, ...)               -> sita_ddk_dm_target_add(type)                           [仅 type 字符串]
 *
 * ⚠ kprobe pre_handler 返回非 0 不会阻止原函数执行（只会跳过其余 probe）。
 * 原 callsite"return 即拦停"的语义在 kprobe 下由"entry 判定 + audit/enforced 阶段 +
 * 对应返回值类函数的 kretprobe"承载；这些 pre_handler 用于审计与采样。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/mman.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/kernel_read_file.h>

#include "sita_ddk_lkm.h"

/* ================= 一、kprobe：callsite 类 ================= */

static int sita_kp_vfs_write(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	const char __user *buf = (const char __user *)regs_get_kernel_argument(regs, 1);
	size_t count = (size_t)regs_get_kernel_argument(regs, 2);
	loff_t pos   = (loff_t)regs_get_kernel_argument(regs, 3);

	return sita_ddk_vfs_write(file, buf, count, &pos);
}

/* vfs_iter_write 与 vfs_iocb_iter_write 共用：均折算成 (file, iter, pos) */
static int sita_kp_iter_write(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	struct iov_iter *iter = (struct iov_iter *)regs_get_kernel_argument(regs, 1);
	loff_t *pos = (loff_t *)regs_get_kernel_argument(regs, 2);

	return sita_ddk_vfs_iter_write(file, iter, pos);
}

static int sita_kp_iocb_write(struct kprobe *kp, struct pt_regs *regs)
{
	struct kiocb *iocb = (struct kiocb *)regs_get_kernel_argument(regs, 0);
	struct iov_iter *iter = (struct iov_iter *)regs_get_kernel_argument(regs, 1);

	return sita_ddk_vfs_iter_write(iocb->ki_filp, iter, &iocb->ki_pos);
}

static int sita_kp_blkdev_write(struct kprobe *kp, struct pt_regs *regs)
{
	struct kiocb *iocb = (struct kiocb *)regs_get_kernel_argument(regs, 0);
	struct iov_iter *from = (struct iov_iter *)regs_get_kernel_argument(regs, 1);

	return sita_ddk_blkdev_write_iter(iocb, from);
}

static int sita_kp_blkdev_fallocate(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	int mode   = (int)regs_get_kernel_argument(regs, 1);
	loff_t start = (loff_t)regs_get_kernel_argument(regs, 2);
	loff_t len   = (loff_t)regs_get_kernel_argument(regs, 3);

	return sita_ddk_blkdev_fallocate(file, mode, start, len);
}

static int sita_kp_blkdev_mmap(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 1);

	return sita_ddk_blkdev_mmap(file, vma);
}

static int sita_kp_blkdev_ioctl(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	unsigned int cmd = (unsigned int)regs_get_kernel_argument(regs, 1);
	struct block_device *bdev = I_BDEV(file_inode(file));

	return sita_ddk_blkdev_ioctl(bdev, cmd);   /* 原型只有 (bdev, cmd) 两参 */
}

static int sita_kp_issue_discard(struct kprobe *kp, struct pt_regs *regs)
{
	struct block_device *bdev = (struct block_device *)regs_get_kernel_argument(regs, 0);
	sector_t sector  = (sector_t)regs_get_kernel_argument(regs, 1);
	sector_t nr_sects = (sector_t)regs_get_kernel_argument(regs, 2);

	return sita_ddk_blkdev_issue_discard(bdev, sector, nr_sects);  /* 无 gfp 参 */
}

static int sita_kp_issue_zeroout(struct kprobe *kp, struct pt_regs *regs)
{
	struct block_device *bdev = (struct block_device *)regs_get_kernel_argument(regs, 0);
	sector_t sector  = (sector_t)regs_get_kernel_argument(regs, 1);
	sector_t nr_sects = (sector_t)regs_get_kernel_argument(regs, 2);

	return sita_ddk_blkdev_issue_zeroout(bdev, sector, nr_sects);  /* 无 gfp/flags 参 */
}

static int sita_kp_dm_table(struct kprobe *kp, struct pt_regs *regs)
{
	const char *type = (const char *)regs_get_kernel_argument(regs, 1);

	return 0;   /* sita_ddk_dm_target_add 返回 void，只审计 */
}

static struct kprobe sita_kps[] = {
	{ .symbol_name = "vfs_write",                 .pre_handler = sita_kp_vfs_write },
	{ .symbol_name = "vfs_iter_write",            .pre_handler = sita_kp_iter_write },
	{ .symbol_name = "vfs_iocb_iter_write",       .pre_handler = sita_kp_iocb_write },
	{ .symbol_name = "blkdev_write_iter",         .pre_handler = sita_kp_blkdev_write },
	{ .symbol_name = "blkdev_fallocate",          .pre_handler = sita_kp_blkdev_fallocate },
	{ .symbol_name = "blkdev_mmap",             .pre_handler = sita_kp_blkdev_mmap },
	{ .symbol_name = "blkdev_ioctl",              .pre_handler = sita_kp_blkdev_ioctl },
	{ .symbol_name = "__blkdev_issue_discard",    .pre_handler = sita_kp_issue_discard },
	{ .symbol_name = "__blkdev_issue_zeroout",    .pre_handler = sita_kp_issue_zeroout },
	{ .symbol_name = "dm_table_add_target",       .pre_handler = sita_kp_dm_table },
};

/* ================= 二、kretprobe：LSM 分发函数类 =================
 * security_xxx 是所有 LSM 的总入口，kretprobe 挂它 = 等效独立 LSM。
 * 模式：entry_handler 里读全部参数、调原 hook 函数（sita_ddk.c 中去 static 后），
 *       把判定结果(0/非0)存入 ri->data；handler 里仅在"拒绝"时覆盖返回值。
 *       绝不在"允许"时写返回值 —— 不影响 SELinux / baseband_guard 的结论。
 * ⚠ entry_handler 运行在 int3 原子上下文：原 hook 内的睡眠操作必须已在
 *   sita_ddk.c 中按 README 2.3 条原子化/裁剪。
 */

/* 宏模板：TARGET=被 probe 的内核函数, FN=原 hook 函数, ARGS=参数读取表达式 */
#define SITA_KR_ENTRY(name, fn, argexpr)                                     \
static int sita_kr_##name##_entry(struct kretprobe_instance *ri,             \
				  struct pt_regs *regs)                      \
{                                                                            \
	*(int *)ri->data = fn(argexpr) ? 1 : 0;                              \
	return 0;                                                            \
}                                                                            \
static int sita_kr_##name(struct kretprobe_instance *ri,                     \
			  struct pt_regs *regs)                              \
{                                                                            \
	if (*(int *)ri->data) {                                              \
		sita_ddk_lkm_hook_enter();                                 \
		regs_set_return_value(regs, -EPERM);                        \
	}                                                                  \
	return 0;                                                            \
}

SITA_KR_ENTRY(bprm, sita_bprm_check_security,
	(struct linux_binprm *)regs_get_kernel_argument(regs, 0))
SITA_KR_ENTRY(fopen, sita_file_open,
	(struct file *)regs_get_kernel_argument(regs, 0))
SITA_KR_ENTRY(fperm, sita_file_permission,
	(struct file *)regs_get_kernel_argument(regs, 0),
	/* 热路径预过滤放在 sita_file_permission 内部（非块设备立即返回） */ 0)

/* file_permission 参数是两个，单独写以便预过滤 */
static int sita_kr_fperm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	int mask = (int)regs_get_kernel_argument(regs, 1);
	struct inode *inode;

	if (!file || !(mask & MAY_WRITE)) return 1;          /* 跳过：非写路径 */
	inode = file_inode(file);
	if (!inode || !S_ISBLK(inode->i_mode)) return 1;    /* 跳过：非块设备 */
	*(int *)ri->data = sita_file_permission(file, mask) ? 1 : 0;
	return 0;
}
static int sita_kr_fperm(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (*(int *)ri->data) {
		sita_ddk_lkm_hook_enter();
		regs_set_return_value(regs, -EPERM);
	}
	return 0;
}

SITA_KR_ENTRY(fioctl, sita_file_ioctl,
	(struct file *)regs_get_kernel_argument(regs, 0),
	(unsigned int)regs_get_kernel_argument(regs, 1),
	(unsigned long)regs_get_kernel_argument(regs, 2))
SITA_KR_ENTRY(mmap, sita_mmap_file,
	(struct file *)regs_get_kernel_argument(regs, 0),
	(unsigned long)regs_get_kernel_argument(regs, 1),
	(unsigned long)regs_get_kernel_argument(regs, 2),
	(unsigned long)regs_get_kernel_argument(regs, 3))
SITA_KR_ENTRY(mprotect, sita_file_mprotect,
	(struct vm_area_struct *)regs_get_kernel_argument(regs, 0),
	(unsigned long)regs_get_kernel_argument(regs, 1),
	(unsigned long)regs_get_kernel_argument(regs, 2))
SITA_KR_ENTRY(ptrace_acc, sita_ptrace_access_check,
	(struct task_struct *)regs_get_kernel_argument(regs, 0),
	(unsigned int)regs_get_kernel_argument(regs, 1))
SITA_KR_ENTRY(ptrace_me, sita_ptrace_traceme,
	(struct task_struct *)regs_get_kernel_argument(regs, 0))
SITA_KR_ENTRY(krf, sita_kernel_read_file,
	(struct file *)regs_get_kernel_argument(regs, 0),
	(enum kernel_read_file_id)regs_get_kernel_argument(regs, 1),
	(bool)regs_get_kernel_argument(regs, 2))
SITA_KR_ENTRY(kld, sita_kernel_load_data,
	(enum kernel_load_data_id)regs_get_kernel_argument(regs, 0),
	(bool)regs_get_kernel_argument(regs, 1))

#define SITA_KR(_n, _sym)                                                \
	{ .kp.symbol_name = (_sym), .entry_handler = sita_kr_##_n##_entry,\
	  .handler = sita_kr_##_n, .data_size = sizeof(int) }

static struct kretprobe sita_krps[] = {
	SITA_KR(bprm,        "security_bprm_check"),
	SITA_KR(fopen,       "security_file_open"),
	{ .kp.symbol_name = "security_file_permission", .entry_handler = sita_kr_fperm_entry,
	  .handler = sita_kr_fperm, .data_size = sizeof(int) },
	SITA_KR(fioctl,      "security_file_ioctl"),
	SITA_KR(mmap,        "security_mmap_file"),
	SITA_KR(mprotect,    "security_file_mprotect"),
	SITA_KR(ptrace_acc,  "security_ptrace_access_check"),
	SITA_KR(ptrace_me,   "security_ptrace_traceme"),
	SITA_KR(krf,         "security_kernel_read_file"),
	SITA_KR(kld,         "security_kernel_load_data"),
};

/* ================= 三、init / exit ================= */
static int __init sita_ddk_lkm_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(sita_kps); i++) {
		ret = register_kprobe(&sita_kps[i]);
		if (ret) {
			pr_err("sita_ddk: kprobe %s failed (%d)\n",
			       sita_kps[i].symbol_name, ret);
			while (i-- > 0) unregister_kprobe(&sita_kps[i]);
			return ret;
		}
	}
	for (i = 0; i < ARRAY_SIZE(sita_krps); i++) {
		ret = register_kretprobe(&sita_krps[i]);
		if (ret) {
			pr_err("sita_ddk: kretprobe %s failed (%d)\n",
			       sita_krps[i].kp.symbol_name, ret);
			while (i-- > 0) unregister_kretprobe(&sita_krps[i]);
			goto err_kp;
		}
	}

	ret = sita_watchdog_start_lkm();
	if (ret) goto err_krp;
	ret = sita_stage_arm_late_lkm();
	if (ret) goto err_krp;

	pr_info("sita_ddk: %zu kprobes + %zu kretprobes armed\n",
		ARRAY_SIZE(sita_kps), ARRAY_SIZE(sita_krps));
	return 0;

err_krp:
	for (i = 0; i < ARRAY_SIZE(sita_krps); i++) unregister_kretprobe(&sita_krps[i]);
err_kp:
	for (i = 0; i < ARRAY_SIZE(sita_kps); i++) unregister_kprobe(&sita_kps[i]);
	return ret;
}
module_init(sita_ddk_lkm_init);

static void __exit sita_ddk_lkm_exit(void)
{
	pr_warn("sita_ddk: refuse to unload, probes are live\n");
}
module_exit(sita_ddk_lkm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sita DDK destructive action guard (kprobe LKM for 6.6 GKI)");
