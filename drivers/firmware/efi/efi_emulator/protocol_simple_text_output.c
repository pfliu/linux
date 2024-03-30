//SPDX-License-Identifier: GPL-2.0

#include "emulator.h"

/* UCS-2 (Universal Coded Character Set) */
static efi_status_t __efiapi output_string(efi_simple_text_output_protocol_t *simple,
						       efi_char16_t *str)
{
	if (print_enabled)
		print_ucs2_string(str);
	return EFI_SUCCESS;
}

struct simple_text_output_mode {
	int32_t	max_mode;
	int32_t	mode;
	int32_t	attribute;
	int32_t	cursor_column;
	int32_t	cursor_row;
	bool	cursor_visible;
};

struct simple_text_output_mode output_mode;

static efi_status_t __efiapi  text_reset(
		efi_simple_text_output_protocol_t *this,
		bool extended_verification)
{
	return EFI_UNSUPPORTED;
}

static efi_status_t __efiapi text_set_attribute(
		efi_simple_text_output_protocol_t *this,
		unsigned int attribute)
{
	return EFI_UNSUPPORTED;
}

efi_simple_text_output_protocol_t text_out = {
	
	.reset = text_reset,
	.output_string = output_string,
	.query_mode = NULL,
	.set_mode = NULL,
	.set_attribute = text_set_attribute,
	.clean_screen = NULL,
	.set_cursor_pos = NULL,
	.enable_cursor = NULL,
	.mode	= &output_mode,
};
