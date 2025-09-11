// SPDX-License-Identifier: GPL-2.0
/*
 * Kexec image bpf section helpers
 *
 * Copyright (C) 2025, 2026 Red Hat, Inc
 */

#define pr_fmt(fmt) "kexec_file(Image): " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kexec.h>
#include <linux/ima.h>
#include <linux/elf.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <asm/byteorder.h>
#include <asm/image.h>
#include <asm/memory.h>
#include "kexec_internal.h"

/* Load a ELF */
static int arm_bpf_prog(char *bpf_elf, unsigned long sz)
{
	return -1;
}

static void disarm_bpf_prog(void)
{
}

struct kexec_context {
	bool kdump;
	char *kernel;
	unsigned long kernel_sz;
	char *initrd;
	unsigned long initrd_sz;
	char *cmdline;
	unsigned long cmdline_sz;
};

void kexec_image_parser_anchor(struct kexec_context *context,
			       unsigned long parser_id);

void noinline __used kexec_image_parser_anchor(struct kexec_context *context,
					       unsigned long parser_id)
{
	barrier();
}

BTF_KFUNCS_START(kexec_modify_return_ids)
BTF_ID_FLAGS(func, kexec_image_parser_anchor, KF_SLEEPABLE)
BTF_KFUNCS_END(kexec_modify_return_ids)

static const struct btf_kfunc_id_set kexec_modify_return_set = {
	.owner = THIS_MODULE,
	.set = &kexec_modify_return_ids,
};

static int __init kexec_bpf_prog_run_init(void)
{
	return register_btf_fmodret_id_set(&kexec_modify_return_set);
}
late_initcall(kexec_bpf_prog_run_init);

static int kexec_buff_parser(struct bpf_parser_context *parser)
{
	return 0;
}

/* At present, only PE format file with .bpf section is supported */
#define file_has_bpf_section pe_has_bpf_section
#define file_get_section pe_get_section

static int kimage_envelope_validate_signature(struct kimage *image)
{
	int ret;

	ret = kexec_kernel_verify_pe_sig(image->kernel_buf,
					 image->kernel_buf_len);
	if (ret) {
		if (get_kexec_sig_enforced()) {
			pr_notice(
				"Enforced kernel signature verification failed (%d).\n",
				ret);
			return ret;
		}

		/*
		 * If IMA is guaranteed to appraise a signature on the kexec
		 * image, permit it even if the kernel is otherwise locked
		 * down.
		 */
		if (!ima_appraise_signature(READING_KEXEC_IMAGE) &&
		    security_locked_down(LOCKDOWN_KEXEC))
			return -EPERM;

		pr_debug("kernel signature verification failed (%d).\n", ret);
	}

	return 0;
}

int decompose_kexec_image(struct kimage *image, int extended_fd)
{
	struct kexec_context context = { 0 };
	struct bpf_parser_context *bpf;
	unsigned long kernel_sz, bpf_sz;
	char *kernel_start, *bpf_start;
	int ret = -EINVAL;

	if (image->type != KEXEC_TYPE_CRASH)
		context.kdump = false;
	else
		context.kdump = true;

	kernel_start = image->kernel_buf;
	kernel_sz = image->kernel_buf_len;

#ifdef CONFIG_KEXEC_SIG
	if (file_has_bpf_section(kernel_start, kernel_sz)) {
		ret = kimage_envelope_validate_signature(image);
		if (ret)
			return ret;
	}
#endif

	while (file_has_bpf_section(kernel_start, kernel_sz)) {
		bpf = alloc_bpf_parser_context(kexec_buff_parser, &context);
		if (!bpf)
			return -ENOMEM;
		file_get_section((const char *)kernel_start, kernel_sz, ".bpf",
				 &bpf_start, &bpf_sz);
		if (!!bpf_sz) {
			/* load and attach bpf-prog */
			ret = arm_bpf_prog(bpf_start, bpf_sz);
			if (ret) {
				put_bpf_parser_context(bpf);
				pr_err("Fail to load .bpf section\n");
				goto err;
			}
		}
		context.kernel = kernel_start;
		context.kernel_sz = kernel_sz;
		/* bpf-prog fentry, which handle above buffers. */
		kexec_image_parser_anchor(&context, (unsigned long)bpf);

		/*
		 * Container may be nested and should be unfold one by one.
		 * The former bpf-prog should prepare 'kernel', 'initrd',
		 * 'cmdline' for the next phase by calling kexec_buff_parser()
		 */
		kernel_start = context.kernel;
		kernel_sz = context.kernel_sz;

		/*
		 * detach the current bpf-prog from their attachment points.
		 */
		disarm_bpf_prog();
		put_bpf_parser_context(bpf);
	}

	/*
	 * image's kernel_buf, initrd_buf, cmdline_buf are set. Now they should
	 * be updated to the new content.
	 */
	if (!!context.kernel) {
		vfree(image->kernel_buf);
		image->kernel_buf = context.kernel;
		image->kernel_buf_len = context.kernel_sz;
	}
	image->initrd_buf = context.initrd;
	image->initrd_buf_len = context.initrd_sz;
	image->cmdline_buf = context.cmdline;
	image->cmdline_buf_len = context.cmdline_sz;

	return 0;
err:
	vfree(context.kernel);
	vfree(context.initrd);
	vfree(context.cmdline);
	return ret;
}
