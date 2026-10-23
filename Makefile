# SPDX-License-Identifier: GPL-2.0
# Sita DDK —— LKM（全 kprobe 方案，目标 6.6 GKI arm64）
#
# ⚠ 目标内核 CONFIG_CFI_CLANG=y 且 CONFIG_WERROR=y：
#   必须用与内核一致的 clang 工具链构建，且零警告。
#   Android GKI 工具链示例（按实际 prebuilts 路径调整）：
TOOLCHAIN ?= $(ANDROID_BUILD_TOP)/prebuilts/clang/host/linux-x86/clang-r510928
KDIR    ?= /path/to/kernel/out  # 含 .config / Module.symvers / 编译产物

export CC      = clang
export LD      = ld.lld
export AR      = llvm-ar
export NM      = llvm-nm
export OBJCOPY = llvm-objcopy
export OBJDUMP = llvm-objdump
export READELF = llvm-readelf
export HOSTCC  = clang
export HOSTCXX = clang++
export HOSTAR  = llvm-ar
export PATH    := $(TOOLCHAIN)/bin:$(PATH)

obj-m += sita_ddk.o
sita_ddk-y := sita_ddk.o sita_kprobe_main.o

ccflags-y += -DSITA_DDK_LKM=1

all:
	$(MAKE) -C $(KDIR) ARCH=arm64 M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) ARCH=arm64 M=$(CURDIR) clean

.PHONY: all clean
