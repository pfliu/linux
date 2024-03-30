/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/nls.h>
#include <linux/efi_emulator.h>

/* Included from drivers/firmware/efi/libstub */
#include <efistub.h>

#define EMULATOR_BASE_ADDR 0

typedef union efi_rng_protocol efi_rng_protocol_t;

union efi_rng_protocol {
	struct {
		efi_status_t (__efiapi *get_info)(efi_rng_protocol_t *,
						  unsigned long *,
						  efi_guid_t *);
		efi_status_t (__efiapi *get_rng)(efi_rng_protocol_t *,
						 efi_guid_t *, unsigned long,
						 u8 *out);
	};
	struct {
		u32 get_info;
		u32 get_rng;
	} mixed_mode;
};

typedef efi_status_t (*uefi_pe_entry)(efi_handle_t handle, efi_system_table_t *systab);

struct efi_pe_instance {
	struct list_head node;
	efi_handle_t handle;
	char *image_file_buf;
	unsigned long image_file_size;
	/* load address for the instance */
	unsigned long image_base;
	unsigned long image_size;
	uefi_pe_entry entry;
};

static inline void __emulator_list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	WRITE_ONCE(prev->next, new);
}

static inline void emulator_list_add(struct list_head *new, struct list_head *head)
{
	__emulator_list_add(new, head, head->next);
}

extern bool print_enabled;
extern struct efi_emulator_param *emulator_param;
extern efi_tcg2_protocol_t emulator_tcg2;
extern efi_cc_protocol_t emulator_cc;
extern efi_rng_protocol_t emulator_rng;
extern efi_simple_text_output_protocol_t text_out;
extern efi_system_table_t systabs;
extern char *heap_start, *heap_end, *heap_cur;

void *aligned_alloc(size_t alignment, size_t size);
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int strcmp(const char *cs, const char *ct);
size_t wcslen(const wchar_t *str);
int wcscmp(const wchar_t *s1, const wchar_t *s2);
int printf(const char *format, ...);
void print_ucs2_string(efi_char16_t* ucs2_str);
extern unsigned long find_image_base_for_handle(efi_handle_t handle);

efi_status_t device_create_handle(efi_handle_t *handle);
efi_status_t device_attach_dev_path(efi_handle_t h, efi_device_path_protocol_t *dp);
efi_status_t device_register_protocol(efi_handle_t handle, efi_guid_t guid,
		void *proto);
efi_status_t device_find_handle_by_path(efi_device_path_protocol_t **dp,
		efi_handle_t *h);
efi_status_t device_handle_protocol(efi_handle_t h, efi_guid_t *uuid,
		void **data);

int efi_device_path_compare(efi_device_path_protocol_t *path1,
		efi_device_path_protocol_t *path2);
size_t efi_device_path_size(efi_device_path_protocol_t *path);
int efi_device_path_clone(efi_device_path_protocol_t *dst,
		efi_device_path_protocol_t *dp);

efi_status_t __emulator_allocate_pages(int alloc_type, int mem_type,
			unsigned long nr_pages, efi_physical_addr_t *addr);
efi_status_t __emulator_allocate_pool(int mem_type, unsigned long sz,
				       void **pool);
efi_status_t emulator_get_memory_map(unsigned long *map_sz,
	void *memmap, unsigned long *map_key, unsigned long *desc_sz,
	unsigned int *desc_version);

efi_status_t conjoin_table(efi_guid_t *uuid, void *table, efi_config_table_t *t);

struct efi_pe_instance *get_instance_by_handle(efi_handle_t h);
struct efi_pe_instance *allocate_pe_instance(char *file_buf, unsigned long size);
int initialize_emulator_service(struct efi_emulator_param *param);
void initialize_heap(struct efi_emulator_param *param);
void load_kernel_pe(struct efi_pe_instance *inst, efi_system_table_t *systabs);
void emulator_main(struct efi_emulator_param *param);
void emulator_entry(struct efi_emulator_param *param);

