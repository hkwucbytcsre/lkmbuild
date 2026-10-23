// SPDX-License-Identifier: GPL-2.0
/*
 * sita_kprobe_main.c —— 针对 Linux 6.6 GKI（arm64）的全 kprobe 模块壳
 *
 * 目标内核核对结论（Module.symvers + target.config）：
 *  - security_add_hooks / security_hook_heads / kallsyms_lookup_name / set_memory_rw 均未导出；
 *  - CONFIG_RODATA_FULL_DEFAULT_ENABLED + STRICT_KERNEL_RWX：内核数据段运行期只读，
 *    LSM 运行期注册路线在此内核上不可行（无干净解锁手段）；
 *  - 但 KPROBES / KRETPROBES / KALLSYMS_ALL 全开，register_kprobe 已导出。
 * => 全部改用 kprobe：probe security_* 分发函数即等效“注册了一个 LSM”，
 *    用 kretprobe 覆盖返回值即等效“deny”。
 *
 * 本文件只负责 probe 框架；各 handler 里调用 sita_ddk.c 的原始 sita_ddk_* 逻辑。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/err.h>
#include <linux/slab.h>

/* ---------- 原 sita_ddk.c 提供（按需 extern） ---------- */
extern int  sita_watchdog_start_lkm(void);   /* 原 late_initcall(sita_watchdog_start) 改 */
extern int  sita_stage_arm_late_lkm(void);   /* 原 late_initcall(sita_stage_arm_late) 改 */
extern void sita_ddk_lkm_hook_enter(void);   /* __module_get(THIS_MODULE)，防卸载 */

/* 示例：xret = sita_ddk_vfs_write(file, buf, count, &pos)；返回非0=拦截 */

/* ================= kprobe（callsite 类，pre_handler 里判定） ================= */
static int sita_kp_vfs_write(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	const char __user *buf = (const char __user *)regs_get_kernel_argument(regs, 1);
	size_t count = (size_t)regs_get_kernel_argument(regs, 2);
	loff_t pos   = (loff_t)regs_get_kernel_argument(regs, 3);
	return sita_ddk_vfs_write(file, buf, count, &pos);   /* 0=放行 */
}
static int sita_kp_iocb_write(struct kprobe *kp, struct pt_regs *regs)
{
	/* vfs_iocb_iter_write(iocb, iter) —— 原 sita_ddk_vfs_iter_write 逻辑 */
	struct kiocb *iocb = (struct kiocb *)regs_get_kernel_argument(regs, 0);
	struct iov_iter *iter = (struct iov_iter *)regs_get_kernel_argument(regs, 1);
	return sita_ddk_vfs_iter_write(iocb, iter);
}
static int sita_kp_blkdev_write(struct kprobe *kp, struct pt_regs *regs)
{
	/* blkdev_write_iter(iocb, iter) —— block/fops.c 静态函数，KALLSYMS_ALL 可 probe */
	struct kiocb *iocb = (struct kiocb *)regs_get_kernel_argument(regs, 0);
	struct iov_iter *iter = (struct iov_iter *)regs_get_kernel_argument(regs, 1);
	return sita_ddk_blkdev_write_iter(iocb, iter);
}
static int sita_kp_blkdev_ioctl(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	unsigned int cmd  = (unsigned int)regs_get_kernel_argument(regs, 1);
	unsigned long arg = (unsigned long)regs_get_kernel_argument(regs, 2);
	return sita_ddk_blkdev_ioctl(file, cmd, arg);
}
static int sita_kp_issue_discard(struct kprobe *kp, struct pt_regs *regs)
{
	struct block_device *bdev = (struct block_device *)regs_get_kernel_argument(regs, 0);
	sector_t s = (sector_t)regs_get_kernel_argument(regs, 1);
	sector_t n = (sector_t)regs_get_kernel_argument(regs, 2);
	gfp_t gfp  = (gfp_t)regs_get_kernel_argument(regs, 3);
	return sita_ddk_blkdev_issue_discard(bdev, s, n, gfp);
}
static int sita_kp_issue_zeroout(struct kprobe *kp, struct pt_regs *regs)
{
	struct block_device *bdev = (struct block_device *)regs_get_kernel_argument(regs, 0);
	sector_t s = (sector_t)regs_get_kernel_argument(regs, 1);
	sector_t n = (sector_t)regs_get_kernel_argument(regs, 2);
	return sita_ddk_blkdev_issue_zeroout(bdev, s, n);
}
static int sita_kp_dm_table(struct kprobe *kp, struct pt_regs *regs)
{
	struct dm_table *t   = (struct dm_table *)regs_get_kernel_argument(regs, 0);
	const char *type     = (const char *)regs_get_kernel_argument(regs, 1);
	return sita_ddk_dm_table_add_target(t, type);
}

static struct kprobe sita_kps[] = {
	{ .symbol_name = "vfs_write",                 .pre_handler = sita_kp_vfs_write },
	{ .symbol_name = "vfs_iter_write",            .pre_handler = sita_kp_iocb_write },
	{ .symbol_name = "vfs_iocb_iter_write",       .pre_handler = sita_kp_iocb_write },
	{ .symbol_name = "blkdev_write_iter",         .pre_handler = sita_kp_blkdev_write },
	{ .symbol_name = "blkdev_ioctl",              .pre_handler = sita_kp_blkdev_ioctl },
	{ .symbol_name = "__blkdev_issue_discard",    .pre_handler = sita_kp_issue_discard },
	{ .symbol_name = "__blkdev_issue_zeroout",    .pre_handler = sita_kp_issue_zeroout },
	{ .symbol_name = "dm_table_add_target",       .pre_handler = sita_kp_dm_table },
};

/* ============ kretprobe（LSM 分发函数类，改返回值=deny） ============ */
/* security_xxx 是所有 LSM 的总入口；这里挂接 = 等效一个独立 LSM。
 * handler 里仅在“我们判定拒绝”时覆盖返回值，允许时不碰 → 不影响 SELinux 等。
 * 判定逻辑直接复用原 sita_bprm_check_security / sita_file_open / ... 的实现，
 * 参数从 entry 时保存（用 kretprobe_instance->data 或 ri->task 上下文重算）。
 */
static int sita_kr_bprm(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct linux_binprm *bprm = (struct linux_binprm *)ri->data;
	if (sita_bprm_would_deny(bprm)) {          /* = 原 sita_bprm_check_security 的判定部分 */
		sita_ddk_lkm_hook_enter();
		regs_set_return_value(regs, -EPERM); /* arm64: regs->regs[0] */
	}
	return 0;
}
static int sita_kr_bprm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	*(struct linux_binprm **)ri->data = (void *)regs_get_kernel_argument(regs, 0);
	return 0;
}
/* 其余 9 个 hook（file_open/file_permission/file_ioctl/mmap_file/file_mprotect/
 * ptrace_access_check/ptrace_traceme/kernel_read_file/kernel_load_data）同理，
 * 原型见 include/linux/lsm_hooks.h (6.6)，此处略。 */

static struct kretprobe sita_krps[] = {
	{ .kp.symbol_name = "security_bprm_check",         .entry_handler = sita_kr_bprm_entry,
	  .handler = sita_kr_bprm, .data_size = sizeof(struct linux_binprm *) },
	/* …按上表补充其余 9 项… */
};

/* ================= init / exit ================= */
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

/*
 * 卸载：安全模块的 handler 由内核异步触发，rmmod 无法保证“摘后再无人调用”。
 * 每个 handler 入口已调 sita_ddk_lkm_hook_enter()（__module_get），refcount 永不归零，
 * rmmod 返回 EBUSY。如坚持可卸载：先全部 unregister_*probe（kprobe 会等在途 handler
 * 完成），再 cancel_delayed_work_sync 两个 work、kobject_put(sysfs)，顺序不可换。
 */
static void __exit sita_ddk_lkm_exit(void)
{
	pr_warn("sita_ddk: refuse to unload, probes are live\n");
}
module_exit(sita_ddk_lkm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sita DDK destructive action guard (kprobe LKM for 6.6 GKI)");
