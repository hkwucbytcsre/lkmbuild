# Sita DDK → LKM 改造指南（基于你的 Module.symvers + target.config 定稿）

## 0. 核对结论：这个内核上 LSM 注册路线走不通，全面改用 kprobe

| 检查项 | 结果 | 影响 |
|---|---|---|
| `security_add_hooks` / `security_hook_heads` | 均未导出 | 运行期注册 LSM 需要符号解析 + 函数指针调用 |
| `set_memory_rw/ro` | **未导出** | 6.6 的 `security_hook_heads` 在 rodata 只读区（本内核开了 `RODATA_FULL`+`STRICT_KERNEL_RWX`），想运行时写它没有干净的解锁手段 |
| `kallsyms_lookup_name` | 未导出 | 无所谓：kprobe 按 `symbol_name` 注册时框架自己解析 |
| `register_kprobe` / `register_kretprobe` | ✓ 已导出 | **主路线成立** |
| `KALLSYMS_ALL=y` | ✓ | **static 函数也可 probe**（`blkdev_write_iter`、`blkdev_ioctl`、甚至 `blkdev_fallocate/blkdev_mmap`） |
| `CONFIG_KPROBES/KRETPROBES` | ✓ | 前提满足 |
| `CONFIG_CFI_CLANG=y`（无 LTO） | ⚠ | 外部模块必须用 clang 构建；handler 都是模块内函数指针调用，CFI 无碍；**不许把内核函数地址强转调用**（这正是放弃 security_add_hooks 的又一理由） |
| `CONFIG_WERROR=y` | ⚠ | 移植代码必须零警告 |
| `CONFIG_MODULE_SIG=y` / `SIG_FORCE` 关 | ✓ | 未签名 ko 可 insmod；若设备 AVB 强制签名校验，用内核 `certs/signing_key.pem` 重签（KSU 环境一般直接 insmod） |
| `CONFIG_KSU=y` | ✓ | 有 root 环境，insmod 可行 |
| `CONFIG_FUNCTION_TRACER` 关 | 中性 | ftrace 挂钩不可用，kprobe 不依赖它，无影响 |
| `CONFIG_PREEMPT=y` | ⚠ | kprobe handler 仍是**原子上下文**：`copy_from_user`→`_inatomic` 版本、`kmalloc`→`GFP_ATOMIC`、禁止互斥锁 |
| `CONFIG_RANDSTRUCT_NONE` / `LTO_NONE` | ✓ | 结构体布局不随机、无 LTO 内联惊喜 |
| SELinux=默认 LSM、`LSM` 列表含 bpf | ✓ | kprobe 方案不注册 LSM、不动 LSM 框架，与 SELinux 零冲突、无需管 lsm= 顺序 |
| `CONFIG_ARM64_MTE`（HW KASAN） | 注意 | 模块内存带 MTE tag，正常编码无碍；别做未对齐/越界访问 |

## 1. 最终架构：全 kprobe 等效替换

### 1.1 原来 10 个 LSM hook → probe 对应的 `security_*` 分发函数
`security_xxx()` 是所有 LSM（含 SELinux）的总入口。用 **kretprobe** 挂它：
- entry_handler 保存参数；
- handler 里跑原 `sita_*` 判定逻辑，**仅当判定“拒绝”时 `regs_set_return_value(regs, -EPERM)`**；允许时不碰返回值 → SELinux 等其他模块的结论原样生效。
- 语义差异说明：原设计是“独立 LSM，deny 优先”；现在变成“在 dispatch 出口覆盖结论”。对我们这种纯 guard 来说等价（拒绝即拒绝），且不影响别的 LSM 放行时的行为。

| 原 hook | probe 目标 | 返回值类型 |
|---|---|---|
| bprm_check_security | `security_bprm_check` | int |
| file_open | `security_file_open` | int |
| file_permission | `security_file_permission` | int |
| file_ioctl | `security_file_ioctl`（已导出，但 kprobe 无需导出） | int |
| mmap_file | `security_mmap_file` | int |
| file_mprotect | `security_file_mprotect` | int |
| ptrace_access_check / ptrace_traceme | `security_ptrace_access_check` / `security_ptrace_traceme` | int |
| kernel_read_file | `security_kernel_read_file` | int |
| kernel_load_data | `security_kernel_load_data` | int |

建议先写个一次性探针模块在真机上 `grep -w security_bprm_check /proc/kallsyms` 确认符号存在（KALLSYMS_ALL 应该有），并确认不在 `/sys/kernel/debug/kprobe/blacklist`。

### 1.2 原来 9 个 callsite → probe 原函数（pre_handler，返回非 0 不影响执行，只记录/审计；要“拦截”用 1.1 的 kretprobe 思路或配合调度）

| 原 callsite | probe 目标 | 说明 |
|---|---|---|
| `vfs_write` | `vfs_write` | 未导出但 KALLSYMS_ALL 有符号 |
| `do_iter_write` | `vfs_iter_write`（其外层，已导出） | 避免 probe static 的 do_iter_write |
| `vfs_iocb_iter_write` | `vfs_iocb_iter_write` | 已导出 |
| `blkdev_write_iter` | `blkdev_write_iter` | static，KALLSYMS_ALL ✓ |
| `blkdev_ioctl` | `blkdev_ioctl` | 同上 |
| `blkdev_issue_discard` | `__blkdev_issue_discard` | 已导出 |
| `blkdev_issue_zeroout` | `__blkdev_issue_zeroout` | 已导出 |
| `dm_table_add_target` | `dm_table_add_target` | DM 是 built-in（`BLK_DEV_DM_BUILTIN=y`），符号在 kallsyms |

pre_handler 返回非 0 只是跳过其余 probe、**不会阻止原函数执行**。原 callsite 里“`return sita_ddk_...` 直接拦停”的语义在 kprobe 下要改：写入类（zero-write 检查）只能在**判定违规时**通过配套 kretprobe 改 `vfs_write` 返回值（返回 -EPERM 且 `file->f_pos` 不动，调用方即报错），或者在 audit 阶段上报。这是改造时最大的语义差异点，建议：audit 阶段（模块加载头 5 分钟本来就是 audit）直接只做记录，enforced 阶段配合 kretprobe 拦截。

## 2. 对 sita_ddk.c 的具体修改清单

1. **删除文件末尾的 LSM 注册**（`DEFINE_LSM`/`security_initcall`），以及 `sita_ddk_add_hooks()`；`sita_hooks[]` 数组可保留（内容就是判定函数，供 kretprobe handler 调用）。
2. **两个 `late_initcall` 改为普通函数** `sita_watchdog_start_lkm()` / `sita_stage_arm_late_lkm()`，由 `sita_kprobe_main.c` 的 module_init 调用。⚠️ stage 状态机：原逻辑假定 boot 最早期注册，现在模块加载时 boot 已完成，`sita_stage_arm_late_lkm()` 里建议先 `sita_advance_stage(XG_STAGE_BOOT_AUDIT, "module_init", NULL)` 再走原 5 分钟 delayed enforce 流程。
3. **原子上下文改造**（逐个函数过一遍，这是主要工作量）：
   - `copy_from_user` → `copy_from_user_inatomic`（失败按“非零/放弃采样”处理）；
   - `kmalloc(GFP_KERNEL)` → `GFP_ATOMIC`；
   - 互斥锁/rwsem 不可在 handler 路径使用，已有 spinlock/atomic 可保留；
   - 内容采样类（`sita_user_write_sample_is_zero` 等）在 `#ifdef SITA_DDK_LKM` 下可整段裁剪（`return false`），并在 sysfs 暴露 `sample_checks=disabled`。
4. **`kernel_kobj` 已导出**，sysfs 部分原样保留。
5. 防卸载：`__module_get(THIS_MODULE)` 已导出，所有 handler 入口第一行调 `sita_ddk_lkm_hook_enter()`。
6. 原 Kconfig/Makefile（树内那套）删除不用；0001 头文件补丁不需要（声明放进模块内）。

## 3. 编译 / 加载 / 验证

```bash
# 用与内核一致的 clang（config 显示 Android clang r510928 / 18.0.0，lld）
make KDIR=/path/to/kernel/out           # 内核 out 目录需有 .config/Module.symvers/编译产物

# 推送到设备（KSU 已 root）
adb push sita_ddk.ko /data/local/tmp/
adb shell "su -c insmod /data/local/tmp/sita_ddk.ko"

dmesg | grep sita_ddk        # 期望: N kprobes + M kretprobes armed / watchdog started / sysfs ready
cat /sys/kernel/sita_ddk/stage
cat /sys/kernel/debug/kprobe/enabled  # =1
```

常见失败：
- `kprobe xxx failed (-22)` → 符号被内联/改名；先在设备上 `grep -w xxx /proc/kallsyms` 确认，确认不了就换邻近函数（如 `blkdev_fallocate` 缺失时改挂 `vfs_fallocate`——`vfs_fallocate` 会走 `security_file_permission`，用 1.1 的 probe 覆盖即可）。
- `kprobe xxx failed (-2)` → 符号在 blacklist，换等效点。
- insmod 报 `Required key not available` → 设备开了模块签名校验，用内核 `certs/signing_key.pem` 签：`scripts/sign-file sha1 certs/signing_key.pem certs/signing_key.x509 sita_ddk.ko`。
- 加载即 panic → 大概率是 handler 里睡眠（dump 栈看 `__might_sleep`），回查第 2.3 条；或 stage 状态机里引用了已释放的 `__init` 内存。

## 4. 回归 checklist
- [ ] 已知 packed ELF 触发 bprm 拦截（audit 日志 + enforced 后 -EPERM）
- [ ] dd 写块设备 / `BLKDISCARD` / `BLKZEROOUT` ioctl 审计日志
- [ ] dm snapshot / verity target 变更出现 OTA 审计日志
- [ ] 加载 5 分钟后 stage 正常切 enforced；watchdog 周期日志
- [ ] `rmmod sita_ddk` 返回 EBUSY
- [ ] 卸载 SELinux 冲突检查：enforcing 模式下正常 App 启动无异常 avc

---

## 5. 改名 sita_ddk 的同步操作（针对你自己的源码树）

骨架里的模块名/函数前缀已全部是 `sita_*`（`sita_kprobe_main.c` 中 extern 的
`sita_ddk_vfs_write` / `sita_watchdog_start_lkm` 等）。你手上的原始源码树需同步改名，
否则链接对不上：

```bash
cd <你的源码树>   # 含 xingguang_ddk.c / kernel_compat.h
find . -type f \( -name '*.c' -o -name '*.h' -o -name 'Makefile' -o -name 'Kconfig' \) \
  -exec sed -i \
    -e 's/xingguang-ddk/sita-ddk/g' \
    -e 's/xingguang_ddk/sita_ddk/g' \
    -e 's/XINGGUANG_DDK/SITA_DDK/g' \
    -e 's/XG_DDK_LKM/SITA_DDK_LKM/g' \
    -e 's/xg_ddk_/sita_ddk_/g' \
    -e 's/xg_/sita_/g' {} +
mv xingguang_ddk.c sita_ddk.c
```

改完后把 `sita_ddk.c`、`kernel_compat.h` 与本目录的 `sita_kprobe_main.c`、`Makefile`
放同一目录即为一个完整外部模块工程（注意 Makefile 里 `sita_ddk-y := sita_ddk.o sita_kprobe_main.o`）。

## 6. 编译需要多少内核源码？（最小构建树）

**结论：必须有一份与设备同 ref 的源码树，但只需跑到 `prepare`，不需要编译内核本体。**
原因是 `make M= modules` 需要三类只能由源码产生的东西：`include/generated/autoconf.h`、
`include/generated/utsrelease.h`、`scripts/`（modpost/genksyms 等 host 工具）。
你的 `Module.symvers` + `.config` 已经把"全编内核"这步省掉了（MODVERSIONS 的 CRC 直接从
Module.symvers 取）。

```bash
# 一次性准备（本地或 CI 相同）
git clone --depth 1 -b oneplus/sm8750_b_16.0.0_oneplus_13_6.6.118     https://github.com/cctv18/android_kernel_common_oneplus_sm8750.git kbuild
cd kbuild
cp /你的/target.config .config
cp /你的/Module.symvers .
# vermagic 对齐：把 uname -r 中 6.6.118 之后的整串写进 LOCALVERSION
# （串里含 -g29d86c5fc9dd，setlocalversion 见到 -g 就不再追加 git 后缀）
scripts/config --set-str LOCALVERSION '-android15-8-g29d86c5fc9dd-abogki428889875-4k'
scripts/config -e LOCALVERSION_AUTO -e MODULES -e KPROBES -e KRETPROBES -e KALLSYMS -e KALLSYMS_ALL
make ARCH=arm64 olddefconfig prepare modules_prepare     # 1~3 分钟，不编 vmlinux
# 模块编译必须用与内核同版本的 clang（vermagic 含编译器串）
make KDIR=$PWD/../kbuild PATH=/path/to/clang-r510928/bin:$PATH \
     CC=clang LD=ld.lld LLVM=1 -C .. 或直接在模块目录 make KDIR=...
```

体积参考：源码树解压约 1.5~2.5GB（SM8750 带 vendor 驱动会更大些）；prepare 产物约 300MB。
跑通后想瘦身可删除 `drivers/ fs/ net/ sound/ Documentation/ tools/`（外部模块构建不读这些
目录），**删完务必重跑一次模块编译验证**再打包保存。CI 里不用删——缓存机制让首次成本只付一次。

**vermagic 校验清单**（`modinfo sita_ddk.ko` 逐项对）：
1. `vermagic` 版本串 = `uname -r`（靠上面的 LOCALVERSION 配方）；
2. clang 版本 = 内核编译器（SM8750 GKI 为 r510928/18.0.0）；
3. `SMP preempt mod_unload modversions` 后缀自动来自 .config，无需干预；
4. 模块未压缩（目标内核未开 MODULE_COMPRESS）✓。

## 6.1 GitHub Actions（.github/workflows/build.yml）

工作流默认就是**上面的最小构建树流程**，不再是全编内核：

- push / PR：克隆 SM8750 分支 → 放 config/symvers → `prepare modules_prepare`（分钟级）
  → r510928 编模块 → `modinfo` 校验 vermagic → 上传 artifact；
- 手动 dispatch 四个参数：`kernel_repo` / `kernel_ref` / `uts_release`（设备完整内核名，
  自动换算成 LOCALVERSION，若与产物不符会判失败）/ `kernel_config_url` / `kernel_symvers_url`；
- 内核构建树按 repo+ref+cfg 缓存，二次运行直接复用。

---

## 7. 与 baseband_guard（BBG，已编入内核的 LSM）共存

**结论：不冲突，可共存，且互补。** BBG 是标准 in-tree LSM（`DEFINE_LSM(baseband_guard)`，
boot 期注册，占用独立 cred blob），hook 为 `file_permission` / `file_ioctl(+compat)` /
`inode_setattr` / `bprm_creds_for_exec` / `cred_prepare/transfer`；**它没有任何 kprobe/
ftrace 插桩**。你的 target.config 里 `CONFIG_LSM` 已含 `baseband_guard`，说明设备内核
已编入，sita_ddk LKM 与其机制完全正交：

| 维度 | BBG（in-tree LSM） | sita_ddk（LKM+kprobe） | 冲突 |
|---|---|---|---|
| 注册机制 | LSM hook 链 + cred blob | kprobe，框架外 | 无（无 blob/顺序竞争） |
| 导出符号/sysfs/日志 tag | 无 | `sita_ddk` 前缀 | 无 |
| 块设备写拦截 | hook 链内（函数体中执行） | kretprobe 挂 `security_file_permission` 出口 | 见下① |
| 破坏性 ioctl | `file_ioctl` hook | `security_file_ioctl` kretprobe + `blkdev_ioctl` probe | 见下① |
| dm snapshot / zero-write 内容检测 / exec 内容检测 | 无 | 独占 | 无 |

**① 同一调用点双判定的语义（关键设计约束）**：deny 叠加。BBG 在 `security_*` 函数体内
执行，我们在函数出口改返回值——执行顺序天然是"BBG 先、sita 后"。因此 sita 的 kretprobe
handler **只允许在判定拒绝时写 `-EPERM`，判定允许时绝不动返回值**（本骨架已按此原则
设计），这样永远不会把 BBG 的拒绝"放行"掉。反过来 BBG 也无法放行 sita 的拒绝。

**共存的四个工程注意项**：

1. **热路径过滤（性能）**：`security_file_permission` 是每次 read/write 都走的超热路径，
   kretprobe 无差别触发（int3+handler）。kretprobe 支持 entry_handler 预过滤——
   非块设备（`!S_ISBLK(file_inode(file)->i_mode)`）或 `!(mask & MAY_WRITE)` 时 entry
   直接返回非 0，handler 不会执行：
   ```c
   static int sita_kr_fperm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
   {
       struct file *f = (struct file *)regs_get_kernel_argument(regs, 0);
       int mask = (int)regs_get_kernel_argument(regs, 1);
       if (!f || !(mask & MAY_WRITE)) return 1;                 /* skip */
       if (!S_ISBLK(file_inode(f)->i_mode)) return 1;           /* skip */
       *(int *)ri->data = mask;
       return 0;
   }
   ```
2. **策略互补，注意 KSU 场景**：BBG 信任 su/magisk/ksu SELinux 域进程（不拦它们写分区）；
   sita 的内容检测不看进程域。KSU root 下跑刷机脚本写分区：BBG 放行、
   sita enforced 可能拦截（这正是 sita 的作用）——两个模块的策略空间不同，不是冲突，
   但测试时要意识到"被谁拒的"。
3. **排障归属**：BBG 的 `BB_ENFORCING` 硬编码为 1，boot 起即生效。若 sita 还处于
   audit 阶段却观察到 `BLKDISCARD` 返回 EPERM，是 **BBG 拒的**，不是 sita——查日志 tag
   `baseband_guard:` vs `sita_ddk:`。
4. **双份日志/冗余判定**：同一 `dd of=/dev/block/by-name/xxx` 会触发两边各一条日志，
   `blkdev_ioctl`+`__blkdev_issue_*` 的 probe 与 BBG 的 file_ioctl 形成双保险，无害；
   介意日志量可在 sita 侧去重（同 inode+pid 短时间窗内只记一次）。

---

## 5.1 让 sita_ddk.c 编译通过（针对 implicit-function-declaration 报错）

**本次报错的直接原因**：构建目录只有骨架（sita_kprobe_main.c + Makefile），缺了
`sita_ddk.c` 本体。完整构建目录需要五件套：

```
<构建目录>/
├── Makefile               # 骨架提供（sita_ddk-y := sita_core.o sita_kprobe_main.o）
├── sita_kprobe_main.c     # 骨架提供
├── sita_ddk_lkm.h         # 骨架提供（模块内部头文件）
├── sita_core.c            # 你的源码（xg→sita 改名后，再由 sita_ddk.c 改名而来！）
└── kernel_compat.h        # 你的源码
```

⚠️ **文件名必须是 sita_core.c，不能叫 sita_ddk.c**：模块名（sita_ddk）与成员目标
（sita_ddk.o）同名会让 Kbuild 报 `Circular sita_ddk.o <- sita_ddk.o dependency dropped`，
且成员文件会被静默跳过不编译（日志里只有 sita_kprobe_main.o 的 CC 行）。
所以 `mv sita_ddk.c sita_core.c` 是必做步骤。

`sita_ddk.c`（原 xingguang_ddk.c 经 sed 改名）还必须做三处适配，否则要么继续报
undeclared、要么链接失败：

**① 换头文件**（原文件 include 的是打进内核树的补丁头文件）：
```bash
sed -i 's|#include <linux/xingguang_ddk.h>|#include "sita_ddk_lkm.h"|' sita_ddk.c
```

**② 10 个 LSM hook 函数去掉 static**（kretprobe handler 要跨文件调用它们）：
```bash
sed -E -i 's/^static int (sita_(bprm_check_security|file_open|file_permission|file_ioctl|mmap_file|file_mprotect|ptrace_access_check|ptrace_traceme|kernel_read_file|kernel_load_data))\(/int \1(/' sita_ddk.c
```
（若尚未跑改名 sed，函数名还是 xg_ 前缀，把上面 sita_ 换成 xg_。）
注意：只去掉这 10 个的 static；`sita_policy_deny`、`sita_sample_opened_script` 等
内部函数保持 static 即可。

**③ 删除末尾注册段**：`sita_ddk_init()` 整个函数、`DEFINE_LSM`/`security_initcall`
两个分支、`sita_ddk_add_hooks()` 调用、`sita_hooks[]` 数组上的 `__lsm_ro_after_init`
（kernel_compat.h 的 SITA_DDK_LKM 分支已清空该宏）；两个 `late_initcall` 改成
`sita_watchdog_start_lkm()` / `sita_stage_arm_late_lkm()` 普通函数。

**原型核对**（handler 与 callsite 已按补丁核对一致，sita_ddk.c 内定义不要改签名）：
`sita_ddk_vfs_iter_write(file, iter, pos)` 是 **3 参**；`sita_ddk_blkdev_ioctl(bdev, cmd)`
**2 参**；`sita_ddk_blkdev_issue_discard/zeroout(bdev, sector, nr_sects)` **3 参**；
`sita_ddk_dm_target_add(const char *type)` **1 参返回 void**。

**⚠ 原子上下文硬约束**：kretprobe entry_handler 在 int3 上下文执行，原 hook 里
`sita_sample_opened_script`（file_open 时读脚本采样）等会睡眠的逻辑**必须在
SITA_DDK_LKM 下裁剪或改 inatomic**，否则加载即 panic（__might_sleep 回溯）。
