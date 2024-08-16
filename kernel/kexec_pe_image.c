// SPDX-License-Identifier: GPL-2.0
/*
 * Kexec image loader

 * Copyright (C) 2024 Red Hat, Inc
 * Author: Pingfan Liu <piliu@redhat.com>
 */

#define pr_fmt(fmt)	"kexec_file(Image): " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/pe.h>
#include <linux/efi.h>
#include <linux/efi_emulator.h>
#include <linux/string.h>
#include <asm/byteorder.h>
#include <asm/cpufeature.h>
#include <asm/image.h>
#include <asm/memory.h>

/*
 * The UEFI Terse Executable (TE) image has MZ header.
*/
static int pe_image_probe(const char *kernel_buf, unsigned long kernel_len)
{
	struct mz_hdr *mz = (struct mz_hdr *)kernel_buf;
	struct pe_hdr *pe;

	if (mz->magic != MZ_MAGIC)
		return -1;
	pe = (struct pe_hdr *)(kernel_buf + mz->peaddr);
	if (pe->magic != PE_MAGIC)
		return -1;

	return 0;
}

/*
 * Efi runtime code or data are marked as EFI_RUNTIME_SERVICES_CODE
 * or EFI_RUNTIME_SERVICES_DATA memory descriptor. When building mapping for the
 * emulator, they should be mapped. Here just recording the entries to those regions.
 */
static void build_rt_info(struct efi_rt_info *rt)
{
	unsigned int desc_size = efi.memmap.desc_size;
	int i, cnt;

	i = cnt = 0;
	if (desc_size) {
		cnt = (efi.memmap.map_end - efi.memmap.map) / desc_size;
		/* The emulator heap memory split the continous memory into three chunk */
		cnt += 2;
	}

	/*
	 * This virtual address is in UEFI address space, and the mapping is recorded
	 * in efi_memory_desc_t[] and passed to reboot kernel.
	 *
	 * EFI stub may use runtime service, so its mapping should be set up
	 */
	rt->runtime = efi.runtime;
	rt->runtime_version = efi.runtime_version;
	rt->runtime_supported_mask = efi.runtime_supported_mask;
	/*
	 * Reconstruct the persistent systab's tables, which are recorded in efi.
	 */
	if (efi.acpi != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.acpi;
		rt->systab_tables[i].guid = ACPI_TABLE_GUID;
		i++;
	}
	if (efi.acpi20 != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.acpi20;
		rt->systab_tables[i].guid = ACPI_20_TABLE_GUID;
		i++;
	}
	if (efi.smbios != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.smbios;
		rt->systab_tables[i].guid = SMBIOS_TABLE_GUID;
		i++;
	}
	if (efi.smbios3 != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.smbios3;
		rt->systab_tables[i].guid = SMBIOS3_TABLE_GUID;
		i++;
	}
	if (efi.esrt != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.esrt;
		rt->systab_tables[i].guid = EFI_SYSTEM_RESOURCE_TABLE_GUID;
		i++;
	}
	if (efi.tpm_log != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.tpm_log;
		rt->systab_tables[i].guid = LINUX_EFI_TPM_EVENT_LOG_GUID;
		i++;
	}
	if (efi.tpm_final_log != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.tpm_final_log;
		rt->systab_tables[i].guid = EFI_TCG2_FINAL_EVENTS_TABLE_GUID;
		i++;
	}
#ifdef CONFIG_LOAD_UEFI_KEYS
	if (efi.mokvar_table != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.mokvar_table;
		rt->systab_tables[i].guid = LINUX_EFI_MOK_VARIABLE_TABLE_GUID;
		i++;
	}
#endif
#ifdef CONFIG_EFI_COCO_SECRET
	if (efi.coco_secret != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.coco_secret;
		rt->systab_tables[i].guid = LINUX_EFI_COCO_SECRET_AREA_GUID;
		i++;
	}
#endif
#ifdef CONFIG_UNACCEPTED_MEMORY
	if (efi.unaccepted != EFI_INVALID_TABLE_ADDR) {
		rt->systab_tables[i].table = (void *)efi.unaccepted;
		rt->systab_tables[i].guid = LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID;
		i++;
	}
#endif
	if (!desc_size) {
		//todo, if noefi boot, LINUX_EFI_MEMRESERVE_TABLE_GUID should be used to pass IMA
	}

	rt->systab_nr_tables = i;

	rt->memmap.map_size = desc_size * cnt;
	/* In case of non-EFI booting, these two fields will be faked later */
	rt->memmap.desc_size = efi.memmap.desc_size;
	rt->memmap.desc_ver = efi.memmap.desc_version;
}

static int create_md_from_res(struct resource *res, void *data)
{
	struct efi_emulator_param *param = (struct efi_emulator_param *)data;
	struct efi_boot_memmap *memmap = &param->rt_info.memmap;
	efi_memory_desc_t *dst_md;

	dst_md = (void *)memmap->map + memmap->map_size;

	/* Split res into three chunk */
	if ((res->start <= param->mempool_start) &&
	      res->end > (param->mempool_start + param->mempool_sz)) {

		dst_md->phys_addr = res->start;
		dst_md->num_pages = (param->mempool_start - res->start) >> EFI_PAGE_SHIFT;
		/* Pretend that it is occupied */
		dst_md->type = EFI_BOOT_SERVICES_DATA;
		dst_md->attribute = EFI_MEMORY_WB;
		dst_md = (void *)dst_md + memmap->desc_size;

		dst_md->phys_addr = param->mempool_start;
		dst_md->num_pages = param->mempool_sz >> EFI_PAGE_SHIFT;
		/* Confine memory footprint inside this region before exit boot service */
		dst_md->type = EFI_CONVENTIONAL_MEMORY;
		dst_md->attribute = EFI_MEMORY_WB;
		dst_md = (void *)dst_md + memmap->desc_size;

		dst_md->phys_addr = param->mempool_start  + param->mempool_sz;
		dst_md->num_pages = (res->end - dst_md->phys_addr) >> EFI_PAGE_SHIFT;
		/* Pretend that it is occupied */
		dst_md->type = EFI_BOOT_SERVICES_DATA;
		dst_md->attribute = EFI_MEMORY_WB;

		memmap->map_size += 3 * (memmap->desc_size);
	} else {
		dst_md->phys_addr = res->start;
		dst_md->num_pages = (res->end - res->start) >> EFI_PAGE_SHIFT;
		/* Pretend that it is occupied */
		dst_md->type = EFI_BOOT_SERVICES_DATA;
		dst_md->attribute = EFI_MEMORY_WB;

		memmap->map_size += memmap->desc_size;
	}

	return 0;
}

static efi_memory_desc_t *conclude_md(efi_memory_desc_t *dst_md,
		unsigned int desc_size, unsigned long pool_start, unsigned long num_pages)
{
	if (dst_md->num_pages == 0)
		return dst_md;

	/* Split into three sections */
	if (dst_md->phys_addr <= pool_start && dst_md->num_pages >= num_pages ) {
		u64 virt_base, phys_base, left_pages, attribute;
		u32 type;

		type = dst_md->type;
		attribute = dst_md->attribute;
		phys_base = dst_md->phys_addr;
		/*
		* After SetVirtualAddressMap, the mapping is installed into
		* firmware and can not be changed. The second kernel should
		* be aware of this info
		*/
		virt_base = dst_md->virt_addr;
		left_pages = dst_md->num_pages;

		dst_md->num_pages = (pool_start - phys_base) >> EFI_PAGE_SHIFT;
		/* Pretend that it is occupied until exit boot service */
		dst_md->type = EFI_BOOT_SERVICES_DATA;
		left_pages -= dst_md->num_pages;

		dst_md = (void *)dst_md + desc_size;
		dst_md->phys_addr = pool_start;
		dst_md->virt_addr = virt_base + (dst_md->phys_addr - phys_base);
		dst_md->num_pages = num_pages;
		dst_md->attribute = attribute;
		/* Confine the memory footprint on it, which has page table mapping */
		dst_md->type = EFI_CONVENTIONAL_MEMORY;
		left_pages -= dst_md->num_pages;

		dst_md = (void *)dst_md + desc_size;
		dst_md->phys_addr = pool_start + (num_pages << EFI_PAGE_SHIFT);
		dst_md->virt_addr = virt_base + (dst_md->phys_addr - phys_base);
		dst_md->num_pages = left_pages;
		dst_md->attribute = attribute;
		/* Pretend that it is occupied until exit boot service */
		dst_md->type = EFI_BOOT_SERVICES_DATA;
	}

	dst_md = (void *)dst_md + desc_size;

	return dst_md;
}

static void create_md_from_efi(efi_memory_desc_t *dst, unsigned int desc_sz,
		struct efi_emulator_param *param)
{
	efi_memory_desc_t *md, *dst_md, *prev_md = NULL;
	unsigned long pool_start, num_pages;

	dst_md = dst;
	pool_start = param->mempool_start;
	num_pages = param->mempool_sz >> EFI_PAGE_SHIFT;
	for_each_efi_memory_desc(md) {
		switch (md->type) {
			// todo, how to ensure kexec dst avoid the EFI_RUNTIME_SERVICES_CODE etc
			case EFI_RUNTIME_SERVICES_CODE:
			case EFI_RUNTIME_SERVICES_DATA:
			case EFI_RESERVED_TYPE:
			case EFI_UNUSABLE_MEMORY:
			case EFI_ACPI_RECLAIM_MEMORY:
				//test whether the current dst_md covers the heap, if yes, split it into three
				dst_md = conclude_md(dst_md, desc_sz, pool_start, num_pages);
				dst_md->phys_addr = md->phys_addr;
				dst_md->virt_addr = md->virt_addr;
				dst_md->num_pages = md->num_pages;
				dst_md->type = md->type;
				dst_md->attribute = md->attribute;
				dst_md = conclude_md(dst_md, desc_sz, pool_start, num_pages);
				break;

			default:
				if (dst_md->num_pages == 0) {
					dst_md->phys_addr = md->phys_addr;
					dst_md->virt_addr = md->virt_addr;
					dst_md->num_pages = md->num_pages;
					/*
					 * Pretend as boot service data to prevent allocation
					 * from it before  efi_exit_boot_services.
					 */
					dst_md->type = EFI_BOOT_SERVICES_DATA;
					dst_md->attribute = md->attribute;
				} else {
					/* merge */
					if (prev_md && prev_md->attribute == md->attribute &&
					(md->phys_addr - prev_md->phys_addr) >> EFI_PAGE_SHIFT == prev_md->num_pages) {
						dst_md->num_pages += md->num_pages;
					} else {
						dst_md = conclude_md(dst_md, desc_sz, pool_start, num_pages);
						dst_md->phys_addr = md->phys_addr;
						dst_md->virt_addr = md->virt_addr;
						dst_md->num_pages = md->num_pages;
						/* Pretend as boot service data */
						dst_md->type = EFI_BOOT_SERVICES_DATA;
						dst_md->attribute = md->attribute;
					}
				}
				break;
		}

		prev_md = md;
	}
	dst_md = conclude_md(dst_md, desc_sz, pool_start, num_pages);
	param->rt_info.memmap.map_size = (void *)dst_md - (void *)dst;
}

/*
 * All efi runtime information should be passed to kexec reboot kernel. Record
 * them in scratch. These information should be in EFI_RUNTIME_SERVICES md, so
 * copying index is enough. Later the mapping for that md will be set up in
 * arch_emulator_prepare_pgtable().
 *
 * If the system is not booted by efi, fake one.
 */
static void encode_efi_runtime_info(struct efi_emulator_param *param, struct kimage *image)
{
	struct efi_rt_info *rt = &param->rt_info;
	efi_memory_desc_t *dst_md;
	unsigned int sz;

	build_rt_info(rt);
	sz = efi.memmap.map_end - efi.memmap.map;
	/* booted by efi firmware */
	if (sz) {
		unsigned long desc_size = efi.memmap.desc_size;

		dst_md = rt->memmap.map;
		/*
		 * It has no point to pass efi.memmap directly to the reboot kernel since
		 * EFI_BOOT_SERVICES_DATA etc has changed. But EFI_RUNTIME_SERVICES_DATA
		 * etc should be paid attention to.
		 */
		create_md_from_efi(dst_md, desc_size, param);
	} else {
		param->noefi_boot = true;
		/*
		* Kernel is booted by non-EFI loader, which parses the PE format. In
		* kexec case, faking memory descriptor so that efi-stub can self-parse.
		* But there is no efi runtime service, and the kernel cmdline should
		* have 'noefi' 
		*/
		rt->memmap.desc_size = sizeof(efi_memory_desc_t);
		rt->memmap.desc_ver = EFI_MEMORY_DESCRIPTOR_VERSION;
		walk_system_ram_res(0, ULONG_MAX, param, create_md_from_res);

		/*
		 * Besides, efi stub removes two dt node '/memreserve', one for initrd
		 * and the other for IMA. EFI_RESERVED_TYPE can not serve that purpose.
		 * That should be handled by LINUX_EFI_MEMRESERVE_TABLE_GUID
		 */
	}
}

extern phys_addr_t arch_emulator_prepare_pgtable(struct kimage *kimage,
		struct efi_emulator_param *param);

static void detect_earlycon(struct efi_emulator_param *param)
{
	//todo, autodetect the console register base and size
	// aarch64 MACHINE_VIRT_UART_BASE
	size_t sz = 15 < strlen("amba-pl011") ? 15 : strlen("amba-pl011");

	memcpy(param->earlycon_name, "amba-pl011", sz);
	param->earlycon_reg_base = 0x9000000;
	param->earlycon_reg_sz = PAGE_SIZE;
	param->print_enabled = true;
}

static phys_addr_t emulator_prepare_pgtable(struct kimage *kimage,
		struct efi_emulator_param *param)
{

	detect_earlycon(param);

	return arch_emulator_prepare_pgtable(kimage, param);
}

/* param, stack, and basic heap */
#define EMULATOR_STACK_SIZE	(1 << 17)
#define EMULATOR_PARAM_SIZE  (1 << 20)

static void *pe_image_load(struct kimage *image,
				char *kernel, unsigned long kernel_len,
				char *initrd, unsigned long initrd_len,
				char *cmdline, unsigned long cmdline_len)
{
	struct kexec_segment *emulator_seg, *param_seg, *kernel_segment;
	struct efi_emulator_param *param;
	struct page *param_pages;
	struct kexec_buf kbuf;
	unsigned long kseg_num;
	int ret;

	image->is_pe = true;
	/* Do not parse image format, just load it. */
	kbuf.image = image;
	kbuf.buf_min = 0;
	kbuf.buf_max = ULONG_MAX;
	kbuf.top_down = false;
	kbuf.buffer = kernel;
	kbuf.bufsz = kernel_len;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	kbuf.memsz = kernel_len;
	kbuf.buf_align = MIN_KIMG_ALIGN;

	kseg_num = image->nr_segments;
	/*
	 * The location of the kernel segment may make it impossible to satisfy
	 * the other segment requirements, so we try repeatedly to find a
	 * location that will work.
	 */
	while ((ret = kexec_add_buffer(&kbuf)) == 0) {
		/* Try to load additional data */
		kernel_segment = &image->segment[kseg_num];
		ret = load_other_segments(image, kernel_segment->mem,
					  kernel_segment->memsz, initrd,
					  initrd_len, cmdline);
		if (!ret)
			break;

		/*
		 * We couldn't find space for the other segments; erase the
		 * kernel segment and try the next available hole.
		 */
		image->nr_segments -= 1;
		kbuf.buf_min = kernel_segment->mem + kernel_segment->memsz;
		kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	}

	if (ret) {
		pr_err("Could not find any suitable kernel location!");
		return ERR_PTR(ret);
	}
	kernel_segment = &image->segment[kseg_num];

	/* Load EFI emulator */
	emulator_seg = &image->segment[image->nr_segments];
	kbuf.buffer = _efi_emulator_start;
	kbuf.bufsz = _efi_emulator_end - _efi_emulator_start;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	kbuf.memsz = kbuf.bufsz;
	kbuf.buf_align = PAGE_SIZE;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		return ERR_PTR(ret);

	/* 
	 * Prepare param and memory for emulator. One page for param,
	 * rear page for stack and the rest for runtime heap.
	 */
	param_seg = &image->segment[image->nr_segments];
	//to do, zero page is not required in kimage_entry_t
	//  and free them
	param_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, 2);
	param = page_to_virt(param_pages);

	/* These chunk of information will be copied to the KEXEC SOURCE PAGE */
	/* emulator loaded address */
	param->load_address = emulator_seg->mem;
	/* PE file payload at the beginning of this RAM range */
	param->kernel_img_start = kernel_segment->mem;
	param->kernel_img_sz = kernel_segment->memsz;
	/* uefi protocol need it */
	param->dtb = image->arch.dtb_mem;
	param->sz_in_byte = utf8s_to_utf16s(cmdline, cmdline_len,
						 UTF16_LITTLE_ENDIAN, param->cmdline, 512);
	param->sz_in_byte *= sizeof(wchar_t);
	kbuf.buffer = param;
	/*
	 * One page for param, one page for stack, the rest for heap, which should
	 *  also has enough room for kernel and its decompression (256MB)
	 */
	kbuf.bufsz = EMULATOR_PARAM_SIZE + kernel_segment->memsz + (1 << 28);
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	kbuf.memsz = kbuf.bufsz;
	kbuf.buf_align = PAGE_SIZE;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		return ERR_PTR(ret);

	/* These info is formed after param segment is built */
	/* stack size equals 64K -sizeof(*param) */
	param->sp = param_seg->mem  + EMULATOR_STACK_SIZE;
	/* heap information */
	param->mempool_start = param->sp;
	param->mempool_sz = kbuf.bufsz - EMULATOR_STACK_SIZE;

	param->pgd_root = emulator_prepare_pgtable(image, param);
	/* For the time being, reset routine will turn off mmu */
	param->mmu_on = false;
	encode_efi_runtime_info(param, image);

	/* relocate.s jumps to it */
	image->start = emulator_seg->mem;
	/* the 3rd input param for restart() */
	image->arch.param_mem = param_seg->mem;
	image->arch.dtb_mem = image->arch.param_mem;

	kexec_dprintk("Loaded emulator at 0x%lx bufsz=0x%lx\n",
		      emulator_seg->mem, emulator_seg->memsz);
	kexec_dprintk("Loaded param blob at 0x%lx bufsz=0x%lx, sp=0x%lx\n",
		      param_seg->mem, param_seg->memsz, param->sp);
	kexec_dprintk("pgd_root:0x%llx\n", param->pgd_root);

	return NULL;
}

const struct kexec_file_ops pe_image_ops = {
	.probe = pe_image_probe,
	.load = pe_image_load,
#ifdef CONFIG_KEXEC_IMAGE_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_pe_sig,
#endif
};
