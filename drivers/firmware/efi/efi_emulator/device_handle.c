//SPDX-License-Identifier: GPL-2.0
#include <linux/efi.h>
#include <asm/efi.h>
#include "emulator.h"

static LIST_HEAD(devices_list);

struct protocol_entry {
	efi_guid_t guid;
	void *proto;
};

/*
 * Drivers can implement their own version of efi_load_file_protocol_t. This represents one.
 * For example, refer to systemd-stub initrd_load_file()
 *
 * BS->InstallMultipleProtocolInterfaces(handle, ...)
 * BS->LocateDevicePath(guid, dp, handle)
 * BS->HandleProtocol(handle, guid, interface)
 * interface->func()
 * This struct can be abstracted to serve EFI_BOOT_SERVICES.LocateDevicePath(guid, dp, handle)
 */
struct device_instance {
	struct list_head node;
	efi_handle_t handle;
	/*
	 * Quote UEFI specification:
	 * 'It is illegal to have two handles in the handle database with identical device paths'
	 */
	efi_device_path_protocol_t *dp;
	/* For simplity, keep the capacity at 8 for the time being */
	struct protocol_entry entries[8];
};

static struct device_instance *find_device_by_handle(efi_handle_t h)
{
	struct device_instance *inst;

	list_for_each_entry(inst, &devices_list, node) {
		if (inst->handle == h)
			return inst;
	}

	return NULL;
}

efi_status_t device_create_handle(efi_handle_t *handle)
{
	struct device_instance *inst;
	int sz;

	sz = sizeof(struct device_instance);
	inst = aligned_alloc(4, sz);
	memset(inst, 0, sz);
	emulator_list_add(&inst->node, &devices_list);
	inst->handle = (efi_handle_t)inst;
	*handle = inst->handle;

	return EFI_SUCCESS;
}

efi_status_t device_attach_dev_path(efi_handle_t h, efi_device_path_protocol_t *dp)
{
	struct device_instance *inst = (struct device_instance *)h;
	int sz;

	sz = efi_device_path_size(dp);
	inst->dp = aligned_alloc(4, sz);
	/* clone the device path */
	efi_device_path_clone(inst->dp, dp);

	return EFI_SUCCESS;
}

/*
 * BS->InstallMultipleProtocolInterfaces() calls down to here.
 *
 * A driver implements its own efi_load_file_protocol_t.
 *
 * According to EFI_LOAD_FILE2_PROTOCOL.LoadFile(), only
 * efi_device_path_protocol_t is required.
 */
efi_status_t device_register_protocol(efi_handle_t handle, efi_guid_t guid,
		void *proto)
{
	struct device_instance *inst;

	inst = find_device_by_handle(handle);
	if (!inst)
		return EFI_NOT_FOUND;

	for (int i = 0; i < 8; i++) {
		if (!efi_guidcmp(inst->entries[i].guid, NULL_GUID)) {
			inst->entries[i].guid = guid;
			inst->entries[i].proto = proto;
			return EFI_SUCCESS;
		}
	}

	return EFI_OUT_OF_RESOURCES;
}

efi_status_t device_find_handle_by_path(efi_device_path_protocol_t **dp,
		efi_handle_t *h)
{
	struct device_instance *inst;
	int ret = -1;

	list_for_each_entry(inst, &devices_list, node) {
		ret = efi_device_path_compare(*dp, inst->dp);
		if (!ret) {
			*h = inst->handle;
			return EFI_SUCCESS;
		}
	}

	return EFI_NOT_FOUND;
}

efi_status_t device_handle_protocol(efi_handle_t h, efi_guid_t *uuid, void **data)
{
	struct device_instance *inst;

	list_for_each_entry(inst, &devices_list, node) {
		if (inst->handle == h) {
			for (int i = 0; i < 8; i++) {
				if (!efi_guidcmp(inst->entries[i].guid, *uuid)) {
					*data = inst->entries[i].proto;
					return EFI_SUCCESS;
				}
			}
			/* no need to try other handles */
			return EFI_NOT_FOUND;
		}
	}

	return EFI_NOT_FOUND;
}
