//SPDX-License-Identifier: GPL-2.0
#include <linux/pe.h>
#include <linux/efi.h>
#include <asm/efi.h>
#include "emulator.h"

#define VALID_PAYLOAD (IMAGE_SCN_CNT_CODE |IMAGE_SCN_CNT_INITIALIZED_DATA |IMAGE_SCN_CNT_UNINITIALIZED_DATA)

/* Refer to PECOFF spec, 'Base Relocation Types' */
#define IMAGE_REL_BASED_ABSOLUTE	0
#define IMAGE_REL_BASED_DIR64	10

unsigned long find_image_base_for_handle(efi_handle_t handle)
{
	struct efi_pe_instance *inst;

	inst = get_instance_by_handle(handle);
	if (!inst)
		return (unsigned long)-1;
	return inst->image_base;
}

typedef struct __packed base_relocation_block {
	uint32_t page_rva;
	uint32_t block_size;
	struct {
	        uint16_t offset : 12;
	        uint16_t type : 4;	/* higher 4-bits in Word */
	} entries[];
} base_relocation_block_t;

static int pe_image_handle_base_relocation(unsigned long base_reloc_table,
		unsigned long sz, unsigned long load_addr, unsigned long delta)
{
	base_relocation_block_t *blk = (base_relocation_block_t *)base_reloc_table;	
	unsigned long page_addr, *target_addr, value;
	uint32_t i, array_num;

	for (; (unsigned long)blk < (base_reloc_table + sz);
	     blk = (base_relocation_block_t *)((unsigned char*)blk + blk->block_size)) {

		/* block_size includes the total base_relocation_block structure */
		array_num = (blk->block_size - sizeof(base_relocation_block_t)) >> 1;
		page_addr = blk->page_rva + load_addr;
		for (i = 0; i < array_num; i++) {
			switch (blk->entries[i].type) {
				case IMAGE_REL_BASED_ABSOLUTE:
					continue;
				case IMAGE_REL_BASED_DIR64:
					target_addr = (unsigned long *)(page_addr + blk->entries[i].offset);
					value = *target_addr + delta;
					*target_addr = value;
					continue;
				default:
					printf("ERR: unhandled reloc type: %d\n");
					return -1; 
			}
		}
	}

	return 0;
}

/*
 * @pe_hdr_offset supplies the size of Dos Header and Stub.
 */ 
static int load_pe(char *file_buf, unsigned long buf_sz, unsigned long pe_hdr_offset,
			struct efi_pe_instance *inst)
{
	unsigned long exec_sz, load_addr, delta;
	unsigned long base_reloc_table, sz;
	struct pe_hdr *pe_hdr;
	struct pe32plus_opt_hdr *opt_hdr;
	struct data_directory *dir;
	struct data_dirent *dirent;
	struct section_header *sect_hdr;
	int section_nr, i;
	char *pe_part_buf, *src, *dst;
	printf("load_pe\n");
	pe_part_buf = file_buf + pe_hdr_offset;
	pe_hdr = (struct pe_hdr *)pe_part_buf;
	if (pe_hdr->opt_hdr_size == 0) {
		printf("ERR: optional header is missing\n");
		return -1;
	}
	section_nr = pe_hdr->sections;
	opt_hdr = (struct pe32plus_opt_hdr *)(pe_part_buf + sizeof(struct pe_hdr));
	sect_hdr = (struct section_header *)((char *)opt_hdr + pe_hdr->opt_hdr_size);
	exec_sz = opt_hdr->image_size;

	/*
	 * PE header must be loaded since some efi stubs parse them e.g. systemd-stub
	 */
	load_addr = (unsigned long)aligned_alloc(opt_hdr->section_align, exec_sz);

	/*
	 * Each section has the same delta. Got the delta based on the first
	 * section's RVA.
	 */
	delta = load_addr - opt_hdr->image_base;
	/* copy PE headers */
	memcpy((void *)load_addr, file_buf, opt_hdr->header_size);

 	/* copy section to segment */
	for (i = 0; i < section_nr; i++) {
		printf("section: %s, relocs: %u\n", sect_hdr->name, sect_hdr->num_relocs);
		if (!(sect_hdr->flags & VALID_PAYLOAD)) {
			sect_hdr++;
			continue;
		}
		/* data_addr is relative to the whole file */
		src = file_buf + sect_hdr->data_addr;
		dst = (char *)(sect_hdr->virtual_address + load_addr);
		memcpy(dst, src, sect_hdr->raw_data_size);
		printf("virtual_address: 0x%u, src: %u, dst: %u\n", sect_hdr->virtual_address, src, dst);
		/*
		 * The SizeOfRawData is rounded but the VirtualSize is not, hence
		 * the former can be greater than latter.
		 */
		if (sect_hdr->virtual_size > sect_hdr->raw_data_size)
			memset(dst + sect_hdr->raw_data_size, 0, sect_hdr->virtual_size - sect_hdr->raw_data_size);
		sect_hdr++;
	}

	/* If there are relocs */
	if (pe_hdr->opt_hdr_size >
	    (offsetof(struct data_directory, base_relocations) + sizeof(struct pe32plus_opt_hdr))) {
		dir = (void *)pe_hdr + sizeof(struct pe_hdr) + sizeof(struct pe32plus_opt_hdr);
		dirent = &dir->base_relocations;
		base_reloc_table = dirent->virtual_address + load_addr;
		sz = dirent->size;
		pe_image_handle_base_relocation(base_reloc_table, sz, load_addr, delta);
	}

	/* Since gcc adheres to ABI, using the current SP is fine for new image instance */

	inst->entry = (uefi_pe_entry)(opt_hdr->entry_point + load_addr);
	inst->image_base = load_addr;
	inst->image_size = opt_hdr->image_size;

	printf("entry_point:0x%lx, delta:0x%lx, final inst's entry at:0x%lx\n",
		opt_hdr->entry_point, delta, inst->entry);
	return 0;
}

static int parse_kernel_pe(struct efi_pe_instance *inst)
{
	char *buf = (char *)inst->image_file_buf;
	u32 pe_hdr_offset;

	pe_hdr_offset = *((u32 *)(buf + 0x3c));
	buf += pe_hdr_offset;
	if (!!memcmp(buf, "PE\0\0", 4)) {
		printf("Not a PE file\n");
		return -1;
	}

	load_pe((char *)inst->image_file_buf, inst->image_file_size,
			pe_hdr_offset, inst);

	return 0;
}

void load_kernel_pe(struct efi_pe_instance *inst, efi_system_table_t *systabs)
{
	int ret;

	ret = parse_kernel_pe(inst);
	if (ret < 0)
		return;
	(*(inst->entry))(inst->handle, systabs);

}
