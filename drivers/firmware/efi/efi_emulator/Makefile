# non-x86 reuses KBUILD_CFLAGS, x86 does not
cflags-y			:= $(KBUILD_CFLAGS)

cflags-$(CONFIG_X86_32)		:= -march=i386
cflags-$(CONFIG_X86_64)		:= -mcmodel=small
cflags-$(CONFIG_X86)		+= -m$(BITS) -D__KERNEL__ \
				   -fno-strict-aliasing -mno-red-zone \
				   -mno-mmx -mno-sse -fshort-wchar \
				   -Wno-pointer-sign \
				   $(call cc-disable-warning, address-of-packed-member) \
				   $(call cc-disable-warning, gnu) \
				   -fno-asynchronous-unwind-tables \
				   $(CLANG_FLAGS)

# arm64 uses the full KBUILD_CFLAGS so it's necessary to explicitly
# disable the stackleak plugin
cflags-$(CONFIG_ARM64)		+= $(DISABLE_STACKLEAK_PLUGIN) \
				   -fno-unwind-tables -fno-asynchronous-unwind-tables
cflags-$(CONFIG_ARM)		+= -DEFI_HAVE_STRLEN -DEFI_HAVE_STRNLEN \
				   -DEFI_HAVE_MEMCHR -DEFI_HAVE_STRRCHR \
				   -DEFI_HAVE_STRCMP -fno-builtin  \
				   $(call cc-option,-mno-single-pic-base)
cflags-$(CONFIG_RISCV)		+= -DNO_ALTERNATIVE -mno-relax
cflags-$(CONFIG_LOONGARCH)	+=

cflags-$(CONFIG_EFI_PARAMS_FROM_FDT)	+= -I$(srctree)/scripts/dtc/libfdt

cflags-y	+= -I drivers/firmware/efi/libstub

KBUILD_CFLAGS			:= $(subst $(CC_FLAGS_FTRACE),,$(cflags-y)) \
				   -Os -DDISABLE_BRANCH_PROFILING \
				   -D__NO_FORTIFY \
				   -ffreestanding \
				   -fno-stack-protector \
				   $(call cc-option,-fno-addrsig) \
				   -D__DISABLE_EXPORTS

#
# struct randomization only makes sense for Linux internal types, which the EFI
# stub code never touches, so let's turn off struct randomization for the stub
# altogether
#
KBUILD_CFLAGS := $(filter-out $(RANDSTRUCT_CFLAGS), $(KBUILD_CFLAGS))

# remove SCS flags from all objects in this directory
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_SCS), $(KBUILD_CFLAGS))
# disable CFI
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_CFI), $(KBUILD_CFLAGS))
# disable LTO
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_LTO), $(KBUILD_CFLAGS))

GCOV_PROFILE			:= n
# Sanitizer runtimes are unavailable and cannot be linked here.
KASAN_SANITIZE			:= n
KCSAN_SANITIZE			:= n
KMSAN_SANITIZE			:= n
UBSAN_SANITIZE			:= n
OBJECT_FILES_NON_STANDARD	:= y

# Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
KCOV_INSTRUMENT			:= n

OBJECT_FILES_NON_STANDARD	:= y
emulator-y			:= head.o entry.o \
				   core.o pe_loader.o memory.o memory_api.o config_table.o misc.o \
				   device_handle.o protocol_simple_text_output.o protocol_device_path.o \
				   lib.o printf.o \
				   amba-pl011.o arm64_proc.o
obj-y				:= efi_emulator.o


EMULATOR_OBJS = $(addprefix $(obj)/,$(emulator-y))

quiet_cmd_ar_emulator = PAD     $@
      cmd_ar_emulator = $(AR) rcSTP $@ $^

$(obj)/emulator.a: $(EMULATOR_OBJS)
	$(call if_changed,ar_emulator)


quiet_cmd_link_emulator = PAD     $@
      cmd_link_emulator = ld -z norelro -z noexecstack -shared --no-undefined -X -Bsymbolic -z notext --emit-relocs --no-apply-dynamic-relocs  \
				-T $(srctree)/drivers/firmware/efi/efi_emulator/arm64_emulator_service.lds \
                                --whole-archive $< --no-whole-archive -o $@


$(obj)/emulator.ro: $(obj)/emulator.a FORCE
	$(call if_changed,link_emulator)


$(obj)/emulator.raw: $(obj)/emulator.ro FORCE
	@$(OBJCOPY)  -O binary -R .note -R .note.gnu.build-id -R .comment -g $< $@

$(obj)/efi_emulator.o: $(obj)/emulator.raw


targets				+= $(emulator-y)


