//SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <asm/efi.h>

#include "emulator.h"

int emulator_initialize(void);

struct efi_emulator_param *emulator_param;
bool print_enabled;

static efi_loaded_image_t loaded_image;

static LIST_HEAD(image_instance_list);

struct efi_pe_instance *get_instance_by_handle(efi_handle_t h)
{
	struct efi_pe_instance *pos;

	list_for_each_entry(pos, &image_instance_list, node)
		if (pos->handle == h)
			return pos;

	return NULL;
}

/* no free path */
struct efi_pe_instance *allocate_pe_instance(char *file_base,
		unsigned long file_size)
{
	struct efi_pe_instance *inst;

	inst = aligned_alloc(8, sizeof(struct efi_pe_instance));
	/* identity */
	inst->handle = (efi_handle_t)inst;
	inst->image_file_buf = file_base;
	inst->image_file_size = file_size;
	emulator_list_add(&inst->node, &image_instance_list);

	return inst;
}

/* The 1st kernel convert cmdline to utf16 and pass to emulator */
static efi_status_t handle_protocol_loaded_image(efi_handle_t h, void **data)
{
	void *base;

	loaded_image.load_options = emulator_param->cmdline;
	loaded_image.load_options_size = emulator_param->sz_in_byte;

	/* loaded address */
	base = (void *)find_image_base_for_handle(h);
	loaded_image.image_base = base;

	*data = &loaded_image;
	return EFI_SUCCESS;

}


static efi_status_t __efiapi emulator_handle_protocol(efi_handle_t h,
				efi_guid_t *uuid, void **data)
{
	if (!efi_guidcmp(*uuid, LOADED_IMAGE_PROTOCOL_GUID))
		return handle_protocol_loaded_image(h, data);
	
	if (!efi_guidcmp(*uuid, EFI_LOAD_FILE2_PROTOCOL_GUID))
		return device_handle_protocol(h, uuid, data);

	return EFI_UNSUPPORTED;
}

/*
 * LocateProtocol() finds the first device handle that support Protocol, and
 * returns a pointer to the protocol interface from that handle in Interface.
 * If no protocol instances are found, then Interface is set to NULL
 */
static efi_status_t __efiapi emulator_locate_protocol(efi_guid_t *uuid,
				void *registration, void **interface)
{
	if (!efi_guidcmp(*uuid, EFI_TCG2_PROTOCOL_GUID)) {
		return EFI_UNSUPPORTED;
	} else if (!efi_guidcmp(*uuid, EFI_CC_MEASUREMENT_PROTOCOL_GUID)) {
		return EFI_UNSUPPORTED;
	} else if (!efi_guidcmp(*uuid, EFI_RNG_PROTOCOL_GUID)) {
		*interface = &emulator_rng;
		return EFI_SUCCESS;
	}

	return EFI_UNSUPPORTED;
}

/* each pair is {efi_guid_t *, void *} */
static efi_status_t __efiapi emulator_install_multiple_protocol_interfaces(efi_handle_t *handle, ...)
{
	efi_status_t ret = EFI_SUCCESS;
	efi_guid_t *guid;
	void *proto;
	va_list args;
	int i;

	if (*handle == 0)
		ret = device_create_handle(handle);

	va_start(args, handle);
	for (i = 0; ret == EFI_SUCCESS; i++) {
		/* If protocol is NULL, then it's the end of the list */
		guid = va_arg(args, efi_guid_t *);
		if (guid == NULL)
			break;
		proto = va_arg(args, void *);
	
		if (!efi_guidcmp(*guid, EFI_DEVICE_PATH_PROTOCOL_GUID)) {
			ret = device_attach_dev_path(*handle, proto);
			continue;
		}
		
		/* install one protocol on the device */
		ret = device_register_protocol(*handle, *guid, proto);
	}
	va_end(args);

	return ret;
}

static efi_status_t __efiapi emulator_uninstall_multiple_protocol_interfaces(efi_handle_t, ...)
{
	return EFI_UNSUPPORTED;
}


// 2do
static efi_status_t __efiapi emulator_allocate_pages(int alloc_type, int mem_type,
			unsigned long nr_pages, efi_physical_addr_t *addr)
{
	return __emulator_allocate_pages(alloc_type, mem_type, nr_pages, addr);
}

// 2do
static efi_status_t __efiapi emulator_free_pages(efi_physical_addr_t addr,
			unsigned long nr_4KB)
{
	return EFI_SUCCESS;

}

static efi_status_t __efiapi emulator_allocate_pool(int mem_type, unsigned long sz,
				       void **pool)
{
	return __emulator_allocate_pool(mem_type, sz, pool);

}

static efi_status_t __efiapi emulator_free_pool(void *pool)
{
	return EFI_SUCCESS;

}

/* memmove() alias as memcpy() */
static void __efiapi emulator_copy_mem(void *dest, const void *src, unsigned long count)
{
	char *tmp;
	const char *s;

	if (dest <= src) {
		tmp = dest;
		s = src;
		while (count--)
			*tmp++ = *s++;
	} else {
		tmp = dest;
		tmp += count;
		s = src;
		s += count;
		while (count--)
			*--tmp = *--s;
	}

}

static void __efiapi emulator_set_mem(void *dst, unsigned long cnt, unsigned char val)
{
	unsigned char *dst_ptr = (char *)dst;
	unsigned long i;

	for (i = 0; i < cnt; i++)
		dst_ptr[i] = val;
}

static efi_status_t __efiapi emulator_stall(unsigned long ms)
{

	return EFI_SUCCESS;
}

static efi_status_t __efiapi emulator_locate_handle(int, efi_guid_t *,
				       void *, unsigned long *,
				       efi_handle_t *)
{
	return EFI_UNSUPPORTED;
}

/*
 * locates all devices on DevicePath that support Protocol and returns the
 * handle to the device that is closest to DevicePath
 */
static efi_status_t __efiapi emulator_locate_device_path(efi_guid_t *guid,
		efi_device_path_protocol_t **dp, efi_handle_t *handle)
{
	efi_status_t ret;
		/* Only one device implements this protocol, so dp can be ignored */
	if (!efi_guidcmp(*guid, EFI_LOAD_FILE2_PROTOCOL_GUID)) {
		ret = device_find_handle_by_path(dp, handle);
		return ret;
	}

	return EFI_NOT_FOUND;
}

static efi_status_t __efiapi emulator_install_configuration_table(efi_guid_t *uuid,
								     void *table)
{
	efi_config_table_t *t = (efi_config_table_t *)systabs.tables;
	int i;

	for (i = 0; i < systabs.nr_tables; i++, t++) {
		if (!efi_guidcmp(t->guid, *uuid))
			return conjoin_table(uuid, table, t);
	}
	t->guid = *uuid;
	t->table = table;
	systabs.nr_tables++;

	return EFI_SUCCESS;
}

/*
 * For UKI, systemd-stub loads linux image and start image.
 * @path: The DeviceHandle specific file path from which the image is loaded
 */
static efi_status_t __efiapi emulator_load_image(bool boot_policy,
		efi_handle_t parent_image, efi_device_path_protocol_t *path,
		void *src_buf, unsigned long src_sz,
		efi_handle_t *handle)
{
	struct efi_pe_instance *inst;
	char *dst;
	
	/* copy the in-memory image */
	if (!!src_buf) {
		dst = aligned_alloc(8, src_sz);
		if (!dst) {
			printf("OOM\n");
			return EFI_OUT_OF_RESOURCES;
		}
		emulator_copy_mem(dst, src_buf, src_sz);
		inst = allocate_pe_instance(dst, src_sz);
		inst->handle = inst;
		*handle = inst->handle;
	/* EFI_SIMPLE_FILE_SYSTEM_PROTOCOL or EFI_LOAD_FILE_PROTOCOL */
	} else {

	}
	return EFI_SUCCESS;
}

static	efi_status_t __efiapi emulator_start_image(efi_handle_t handle,
		unsigned long *exit_data_sz, efi_char16_t **exit_data)
{

	struct efi_pe_instance *inst;

	inst = get_instance_by_handle(handle);
	if (unlikely(!inst)) {
		printf("error: can not find image\n");
		return EFI_NOT_FOUND;
	}
	load_kernel_pe(inst, &systabs);

	return EFI_SUCCESS;
}

/*
 * As the final stage, destroy the boottime context, e.g. release the memory
 * occupied by some data struct.
 */
static efi_status_t __efiapi emulator_exit_boot_services(efi_handle_t handle,
							    unsigned long map_key)
{
	return EFI_SUCCESS;
}

static efi_boot_services_t bt_services = {
	.handle_protocol = emulator_handle_protocol,
	.locate_protocol = emulator_locate_protocol,
	.install_multiple_protocol_interfaces = emulator_install_multiple_protocol_interfaces,
	.uninstall_multiple_protocol_interfaces = emulator_uninstall_multiple_protocol_interfaces,

	.allocate_pool = emulator_allocate_pool,
	.free_pool = emulator_free_pool,
	.allocate_pages = emulator_allocate_pages,
	.free_pages = emulator_free_pages,
	.copy_mem = emulator_copy_mem,
	.set_mem = emulator_set_mem,
	.get_memory_map = emulator_get_memory_map,

	.stall = emulator_stall,

	.locate_handle = emulator_locate_handle,
	.locate_device_path = emulator_locate_device_path,
	.install_configuration_table = emulator_install_configuration_table,
	.load_image = emulator_load_image,
	.start_image = emulator_start_image,
	.exit_boot_services = emulator_exit_boot_services,
};

static efi_char16_t vendor[] = u"Linux Kexec";

static efi_status_t unsupported_func(void)
{
	return EFI_UNSUPPORTED;
}

efi_system_table_t systabs = {
	.hdr = {
		.signature = EFI_SYSTEM_TABLE_SIGNATURE,
	},
	.fw_vendor = (unsigned long)vendor,
	.fw_revision = 0x10001,
	.con_in_handle = 0x0,
	.con_in = (efi_simple_text_input_protocol_t *)unsupported_func,
	.con_out_handle = 0x0,
	.con_out = &text_out,
	.stderr_handle = 0x0,
	/* Per specification, A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL */
	.stderr = (unsigned long)unsupported_func,
	/* Passed in by the 1st kernel */
	.runtime = NULL,
	.boottime = &bt_services,
	.nr_tables = 0,
	.tables = 0,
};

static efi_rt_properties_table_t rt_support = {
	.runtime_services_supported = 0,
};

int initialize_emulator_service(struct efi_emulator_param *param)
{

	efi_config_table_t *tables;
	unsigned int i;

	printf("initialize_emulator_service, dtb=0x%lx, mempool_start=0x%lx, end:0x%lx\n",
			param->dtb, param->mempool_start, param->mempool_start + param->mempool_sz);
	emulator_param = param;
	print_enabled = param->print_enabled;
	i = param->rt_info.systab_nr_tables;
	systabs.tables = (unsigned long)&param->rt_info.systab_tables;
	tables = param->rt_info.systab_tables;
	tables[i].guid = DEVICE_TREE_GUID;
	tables[i].table = (void *)param->dtb;
	i++;
	if (!param->noefi_boot) {
		rt_support.runtime_services_supported = param->rt_info.runtime_supported_mask;
	}
	tables[i].guid = EFI_RT_PROPERTIES_TABLE_GUID;
	tables[i].table = (void *)&rt_support;
	i++;
	systabs.nr_tables = i;

	systabs.runtime = (efi_runtime_services_t *)param->rt_info.runtime;
	return 0;
}
