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
#include <linux/module_signature.h>
#include <linux/verification.h>
#include <asm/byteorder.h>
#include <linux/decompress/generic.h>
#include "kexec_internal.h"

#include "kexec_bpf/kexec_pe_parser_bpf.lskel.h"

static struct kexec_pe_parser_bpf *pe_parser;

static void *get_symbol_from_elf(const char *elf_data, size_t elf_size,
				 const char *symbol_name,
				 unsigned int *symbol_size)
{
	Elf_Ehdr *ehdr = (Elf_Ehdr *)elf_data;
	Elf_Shdr *shdr, *dst_shdr;
	const Elf_Sym *sym;
	void *symbol_data;

	/* Check minimum size for ELF header */
	if (elf_size < sizeof(Elf_Ehdr)) {
		pr_err("ELF file too small\n");
		return NULL;
	}

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		pr_err("Not a valid ELF file\n");
		return NULL;
	}

	/* Check section header table bounds */
	if (ehdr->e_shoff > elf_size ||
	    ehdr->e_shoff + (ehdr->e_shnum * sizeof(Elf_Shdr)) > elf_size) {
		pr_err("Section header table out of bounds\n");
		return NULL;
	}

	sym = elf_find_symbol(ehdr, elf_size, symbol_name);
	if (!sym)
		return NULL;

	/* Check symbol section index */
	if (sym->st_shndx >= ehdr->e_shnum) {
		pr_err("Symbol section index out of bounds\n");
		return NULL;
	}

	shdr = (struct elf_shdr *)(elf_data + ehdr->e_shoff);
	dst_shdr = &shdr[sym->st_shndx];

	/* Check section data bounds */
	if (dst_shdr->sh_offset > elf_size ||
	    dst_shdr->sh_size > elf_size - dst_shdr->sh_offset)
		return NULL;
	/* Check symbol start offset fits within the section */
	else if (sym->st_value > dst_shdr->sh_size)
		return NULL;
	/* Check symbol extent (st_value + st_size) fits within the section */
	else if (sym->st_size > dst_shdr->sh_size - sym->st_value)
		return NULL;

	symbol_data = (void *)(elf_data + dst_shdr->sh_offset + sym->st_value);
	if (symbol_size)
		*symbol_size = sym->st_size;

	return symbol_data;
}

/* Load a ELF */
static int arm_bpf_prog(char *bpf_elf, unsigned long sz)
{
	opts_data = get_symbol_from_elf(bpf_elf, sz, "opts_data", &opts_data_sz);
	opts_insn = get_symbol_from_elf(bpf_elf, sz, "opts_insn", &opts_insn_sz);
	if (!opts_data || !opts_insn) {
		pr_err("Cannot get symbol from ELF: opts_data=%px, opts_insn=%px\n",
			opts_data, opts_insn);
		return -1;
	}

	if (opts_data_sz < 1 || opts_insn_sz < 1) {
		pr_err("Symbol size too small (opts_data_sz=%u, opts_insn_sz=%u)\n",
		       opts_data_sz, opts_insn_sz);
		return -1;
	}
	/*
	 * When light skeleton generates opts_data[] and opts_insn[], it appends a
	 * NULL terminator at the end of string
	 */
	opts_data_sz = opts_data_sz - 1;
	opts_insn_sz = opts_insn_sz - 1;

	pe_parser = kexec_pe_parser_bpf__open_and_load();
	if (!pe_parser) {
		pr_info("Can not open and load bpf parser\n");
		return -1;
	}

	return kexec_pe_parser_bpf__attach(pe_parser);
}

static void disarm_bpf_prog(void)
{
	kexec_pe_parser_bpf__destroy(pe_parser);
	pe_parser = NULL;
	opts_data = NULL;
	opts_insn = NULL;
}

#define MAX_PARSING_BUF_NUM    16

typedef enum {
	SIG_ENFORCE_NONE = 0,
	SIG_ENFORCE_SIG  = 1,
	SIG_ENFORCE_IMA  = 2,
} kexec_sig_enforced;

struct kexec_context {
	bool kdump;
	bool parsed;
	kexec_sig_enforced sig_mode;
	char *parsing_buf[MAX_PARSING_BUF_NUM];
	unsigned long parsing_buf_sz[MAX_PARSING_BUF_NUM];
	char *next_parsing_buf[MAX_PARSING_BUF_NUM];
	unsigned long next_parsing_buf_sz[MAX_PARSING_BUF_NUM];

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

/* Mark the bpf parser success */
#define KEXEC_BPF_CMD_INVALID		0x0
#define KEXEC_BPF_CMD_DONE		0x1
#define KEXEC_BPF_CMD_DECOMPRESS	0x2
#define KEXEC_BPF_CMD_COPY		0x3
#define KEXEC_BPF_CMD_VERIFY_SIG	0x4

#define KEXEC_BPF_SUBCMD_INVALID	0x0
#define KEXEC_BPF_SUBCMD_KERNEL		0x1
#define KEXEC_BPF_SUBCMD_INITRD		0x2
#define KEXEC_BPF_SUBCMD_CMDLINE	0x3

#define KEXEC_BPF_PIPELINE_INVALID	0x0
#define KEXEC_BPF_PIPELINE_FILL		0x1

struct cmd_hdr {
	uint16_t cmd;
	uint8_t subcmd;
	uint8_t pipeline_flag;
	/* sizeof(chunks) + sizeof(all data) */
	uint32_t payload_len;
	/* 0 */
	uint16_t num_chunks;
} __packed;

/* Reserved for extension */
struct cmd_chunk {
	uint16_t type;
	uint32_t len;
} __packed;

/*
 * This function is only called from BPF programs hooked at
 * kexec_image_parser_anchor(). Therefore, it is only invoked in the
 * kexec_file_load path, which is not reentrant.
 */
static int kexec_buff_parser(struct bpf_parser_context *parser)
{
	struct bpf_parser_buf *pbuf = parser->buf;
	struct kexec_context *ctx = (struct kexec_context *)parser->data;
	struct cmd_hdr *cmd;
	char *decompressed_buf, *buf, *p, *pn;
	unsigned long decompressed_sz;
	bool fill_pipeline = false;
	int i, ret = -EINVAL;

	if (pbuf->size < sizeof(struct cmd_hdr))
		return -EINVAL;

	cmd = (struct cmd_hdr *)pbuf->buf;
	if (cmd->payload_len > pbuf->size - sizeof(struct cmd_hdr))
		return -EINVAL;

	buf = pbuf->buf + sizeof(struct cmd_hdr);
	if (cmd->payload_len + sizeof(struct cmd_hdr) > pbuf->size) {
		pr_info("Invalid payload size:0x%x, while buffer size:0x%x\n",
				cmd->payload_len, pbuf->size);
		return -EINVAL;
	}
	fill_pipeline = cmd->pipeline_flag & KEXEC_BPF_PIPELINE_FILL;
	switch (cmd->cmd) {
	case KEXEC_BPF_CMD_DONE:
		ctx->parsed = true;
		break;
	case KEXEC_BPF_CMD_DECOMPRESS:
		ret = post_boot_decompress(buf, cmd->payload_len, &decompressed_buf,
					&decompressed_sz);
		if (!ret) {
			switch (cmd->subcmd) {
			case KEXEC_BPF_SUBCMD_KERNEL:
				/*
				 * The image may consist of multiple layers. An outer parser cannot
				 * determine whether the parsed result is terminal, so it forwards
				 * the result to the next layer.
				 *
				 * A parser may skip KEXEC_BPF_PIPELINE_FILL based on the image
				 * format specification.
				 */
				if (fill_pipeline) {
					for (i = 0; i < MAX_PARSING_BUF_NUM; i++) {
						if (!ctx->next_parsing_buf[i])
							break;
					}
					/* No enough parsing slot */
					if (i == MAX_PARSING_BUF_NUM) {
						vfree(decompressed_buf);
						return -ENOMEM;
					}
					p = __vmalloc(decompressed_sz, GFP_KERNEL | __GFP_ACCOUNT);
					if (!p) {
						vfree(decompressed_buf);
						return -ENOMEM;
					}
				}

				vfree(ctx->kernel);
				ctx->kernel = decompressed_buf;
				ctx->kernel_sz = decompressed_sz;
				if (fill_pipeline) {
					memcpy(p, decompressed_buf, decompressed_sz);
					ctx->next_parsing_buf[i] = p;
					ctx->next_parsing_buf_sz[i] = decompressed_sz;
				}
				break;
			default:
				vfree(decompressed_buf);
				ret = -EINVAL;
				break;
			}
		}
		break;
	case KEXEC_BPF_CMD_COPY:
		switch (cmd->subcmd) {
		case KEXEC_BPF_SUBCMD_KERNEL:
			if (cmd->payload_len == 0)
				return -EINVAL;
			break;
		case KEXEC_BPF_SUBCMD_INITRD:
			if (cmd->payload_len == 0)
				return 0;
			break;
		case KEXEC_BPF_SUBCMD_CMDLINE:
			if (cmd->payload_len == 0)
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
		p = __vmalloc(cmd->payload_len, GFP_KERNEL | __GFP_ACCOUNT);
		if (!p)
			return -ENOMEM;
		memcpy(p, buf, cmd->payload_len);
		if (fill_pipeline) {
			for (i = 0; i < MAX_PARSING_BUF_NUM; i++) {
				if (!ctx->next_parsing_buf[i])
					break;
			}
			/* No enough parsing slot */
			if (i == MAX_PARSING_BUF_NUM) {
				vfree(p);
				return -ENOMEM;
			}
			pn = __vmalloc(cmd->payload_len, GFP_KERNEL | __GFP_ACCOUNT);
			if (!pn) {
				vfree(p);
				return -ENOMEM;
			}
			memcpy(pn, buf, cmd->payload_len);
			ctx->next_parsing_buf[i] = pn;
			ctx->next_parsing_buf_sz[i] = cmd->payload_len;
		}

		switch (cmd->subcmd) {
		case KEXEC_BPF_SUBCMD_KERNEL:
			vfree(ctx->kernel);
			ctx->kernel = p;
			ctx->kernel_sz = cmd->payload_len;
			break;
		/* Todo: allow the concatenation of multiple initrd */
		case KEXEC_BPF_SUBCMD_INITRD:
			vfree(ctx->initrd);
			ctx->initrd = p;
			ctx->initrd_sz = cmd->payload_len;
			break;
		/* Todo: allow the concatenation of multiple cmdline */
		case KEXEC_BPF_SUBCMD_CMDLINE:
			vfree(ctx->cmdline);
			ctx->cmdline = NULL;
			if (p[cmd->payload_len - 1] != '\0') {
				char * p2;

				p2 = __vmalloc(cmd->payload_len + 1, GFP_KERNEL | __GFP_ACCOUNT);
				if (!p2) {
					vfree(p);
					return -ENOMEM;
				}
				memcpy(p2, p, cmd->payload_len);
				p2[cmd->payload_len] = '\0';
				vfree(p);
				ctx->cmdline = p2;
				ctx->cmdline_sz = cmd->payload_len + 1;

			} else {
				ctx->cmdline = p;
				ctx->cmdline_sz = cmd->payload_len;
			}
			break;
		default:
			vfree(p);
			break;
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

#define KEXEC_ELF_BPF_PREFIX		".bpf."
#define KEXEC_ELF_BPF_NESTED		".bpf.nested"
#define KEXEC_ELF_BPF_MAX_IDX		8
#define KEXEC_ELF_BPF_MAX_DEPTH		4

static bool is_elf64_image(const char *buf, size_t sz)
{
	if (sz < EI_CLASS + 1)
		return false;
	if (memcmp(buf, ELFMAG, SELFMAG) != 0)
		return false;
	return buf[EI_CLASS] == ELFCLASS64;
}

/*
 * elf_get_shstrtab - resolve the section-name string table of an ELF image
 * @buf:       ELF image buffer
 * @sz:        buffer length
 * @ehdr_out:  receives a pointer to the ELF header inside @buf
 * @shdrs_out: receives a pointer to the section-header table inside @buf
 * @shstrtab_out: receives a pointer to the section-name string table
 *
 * All output pointers are interior pointers into @buf; callers must not
 * free them independently.
 *
 * Returns 0 on success, -EINVAL if any structural check fails.
 */
static int elf_get_shstrtab(const char *buf, size_t sz,
			    const Elf64_Ehdr **ehdr_out,
			    const Elf64_Shdr **shdrs_out,
			    const char **shstrtab_out)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	const Elf64_Shdr *shstr_shdr;

	if (sz < sizeof(*ehdr))
		return -EINVAL;

	ehdr = (const Elf64_Ehdr *)buf;

	if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
		return -EINVAL;

	if (ehdr->e_shstrndx >= ehdr->e_shnum)
		return -EINVAL;

	/* section-header table must fit inside the buffer */
	if (ehdr->e_shoff > sz ||
	    ehdr->e_shnum > (sz - ehdr->e_shoff) / sizeof(Elf64_Shdr))
		return -EINVAL;

	shdrs = (const Elf64_Shdr *)(buf + ehdr->e_shoff);
	shstr_shdr = &shdrs[ehdr->e_shstrndx];

	/* string table itself must fit inside the buffer */
	if (shstr_shdr->sh_offset > sz ||
	    shstr_shdr->sh_size > sz - shstr_shdr->sh_offset)
		return -EINVAL;

	*ehdr_out     = ehdr;
	*shdrs_out    = shdrs;
	*shstrtab_out = buf + shstr_shdr->sh_offset;

	return 0;
}

/*
 * verify_elf_sig - verify PKCS#7 signature appended to a signed ELF
 * @payload: pointer to ELF data
 * @pay_len: length of ELF data including appended signature trailer
 *
 * The appended signature format is produced by scripts/sign-file:
 *
 *   [ ELF data ][ PKCS#7 ][ struct module_signature ][ MODULE_SIG_STRING ]
 *
 * Verification is attempted against secondary trusted keyring, then
 * platform keyring.
 *
 * Returns 0 on success, negative errno otherwise.
 */
static int verify_elf_sig(const char *payload, u32 pay_len)
{
	const struct module_signature *ms;
	size_t sig_len, data_len = pay_len;
	int ret;

	if (pay_len <= sizeof(MODULE_SIG_STRING) - 1 + sizeof(*ms))
		goto no_sig;

	data_len -= sizeof(MODULE_SIG_STRING) - 1;
	if (memcmp(payload + data_len, MODULE_SIG_STRING,
		   sizeof(MODULE_SIG_STRING) - 1) != 0)
		goto no_sig;

	data_len -= sizeof(*ms);
	ms = (const struct module_signature *)(payload + data_len);

	sig_len = be32_to_cpu(ms->sig_len);
	if (sig_len == 0 || sig_len > data_len) {
		pr_err("kexec verify_sig_elf: malformed signature trailer\n");
		return -EBADMSG;
	}

	data_len -= sig_len;

	ret = verify_pkcs7_signature(payload, data_len, payload + data_len,
				     sig_len, VERIFY_USE_SECONDARY_KEYRING,
				     VERIFYING_MODULE_SIGNATURE, NULL, NULL);
	if (ret) {
		pr_debug(
			"kexec verify_sig_elf: secondary keyring failed (%d), trying platform\n",
			ret);
		ret = verify_pkcs7_signature(payload, data_len,
					     payload + data_len, sig_len,
					     VERIFY_USE_PLATFORM_KEYRING,
					     VERIFYING_MODULE_SIGNATURE, NULL,
					     NULL);
	}

	if (ret)
		pr_err("kexec verify_sig_elf: signature verification failed: %d\n",
		       ret);
	return ret;

no_sig:
	if (get_kexec_sig_enforced()) {
		pr_err("kexec verify_sig_elf: missing signature and sig_enforce is set\n");
		return -EKEYREJECTED;
	}
	return 0;
}

/*
 * validate_elf_bpf_sections - enforce the section-naming contract
 * @buf: ELF image buffer
 * @sz:  buffer length
 *
 * Every section other than the null entry (index 0) and ".shstrtab" must
 * be named either ".bpf.N" (N in 1..KEXEC_ELF_BPF_MAX_IDX, no gaps, no
 * duplicates) or ".bpf.nested" (at most once).  Any other name, any
 * duplicate, or a gap in the numeric sequence is an error.
 *
 * Returns 0 if the ELF passes all checks, -EINVAL otherwise.
 */
static int validate_elf_bpf_sections(const char *buf, size_t sz)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	const Elf64_Shdr *shstr_shdr;
	const char *shstrtab;
	bool seen[KEXEC_ELF_BPF_MAX_IDX + 1] = {};
	bool seen_nested = false;
	int max_idx = 0;
	int ret;
	int i;

	/* At present, it only supports 64-bits arch */
	if (!is_elf64_image(buf, sz))
		return -EINVAL;

	ret = elf_get_shstrtab(buf, sz, &ehdr, &shdrs, &shstrtab);
	if (ret)
		return ret;

	shstr_shdr = &shdrs[ehdr->e_shstrndx];
	if (shstr_shdr->sh_size == 0 || shstrtab[shstr_shdr->sh_size - 1] != '\0') {
		pr_err("kexec: ELF string table is not null-terminated\n");
		return -EINVAL;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		const char *name;
		const char *num_str;
		int idx;

		if (shdrs[i].sh_name >= shstr_shdr->sh_size)
			return -EINVAL;

		name = shstrtab + shdrs[i].sh_name;

		/* structural ELF sections: null entry and section-name table */
		if (name[0] == '\0' || strcmp(name, ".shstrtab") == 0)
			continue;

		/* .bpf.nested must appear at most once */
		if (strcmp(name, KEXEC_ELF_BPF_NESTED) == 0) {
			if (seen_nested) {
				pr_err("kexec: duplicate .bpf.nested section\n");
				return -EINVAL;
			}
			seen_nested = true;
			continue;
		}

		/* every remaining section must start with the ".bpf." prefix */
		if (strncmp(name, KEXEC_ELF_BPF_PREFIX,
			    sizeof(KEXEC_ELF_BPF_PREFIX) - 1) != 0) {
			pr_err("kexec: invalid ELF section name: %s\n", name);
			return -EINVAL;
		}

		/*
		 * Suffix must be exactly one digit in [1, KEXEC_ELF_BPF_MAX_IDX].
		 * Multi-digit numbers and leading zeros are rejected.
		 */
		num_str = name + sizeof(KEXEC_ELF_BPF_PREFIX) - 1;
		if (num_str[0] < '1' ||
		    num_str[0] > '0' + KEXEC_ELF_BPF_MAX_IDX ||
		    num_str[1] != '\0') {
			pr_err("kexec: invalid BPF section index in: %s\n", name);
			return -EINVAL;
		}

		idx = num_str[0] - '0';
		if (seen[idx]) {
			pr_err("kexec: duplicate BPF section: %s\n", name);
			return -EINVAL;
		}
		seen[idx] = true;
		if (idx > max_idx)
			max_idx = idx;
	}

	/* indices must be consecutive starting from 1 */
	for (i = 1; i <= max_idx; i++) {
		if (!seen[i]) {
			pr_err("kexec: missing .bpf.%d section\n", i);
			return -EINVAL;
		}
	}

	/* It is right format, now check its signature */
	ret = verify_elf_sig(buf, sz);
	if (ret)
		return ret;


	return 0;
}

/*
 * elf_find_section - locate a named section in an ELF image
 * @buf:     ELF image buffer
 * @sz:      buffer length
 * @name:    section name to find
 * @out_buf: receives a pointer to the section data (NULL if not found)
 * @out_sz:  receives the section size in bytes (0 if not found)
 *
 * Returns 0 on success (including the "not found" case), -EINVAL on a
 * structural error.
 */
static int elf_find_section(const char *buf, size_t sz, const char *name,
			    char **out_buf, size_t *out_sz)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	const Elf64_Shdr *shstr_shdr;
	const char *shstrtab;
	int ret;
	int i;

	ret = elf_get_shstrtab(buf, sz, &ehdr, &shdrs, &shstrtab);
	if (ret)
		return ret;

	shstr_shdr = &shdrs[ehdr->e_shstrndx];

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdrs[i].sh_name >= shstr_shdr->sh_size)
			return -EINVAL;

		if (strcmp(shstrtab + shdrs[i].sh_name, name) != 0)
			continue;

		/* section data must be within the buffer */
		if (shdrs[i].sh_offset > sz ||
		    shdrs[i].sh_size > sz - shdrs[i].sh_offset)
			return -EINVAL;

		*out_buf = (char *)(buf + shdrs[i].sh_offset);
		*out_sz  = shdrs[i].sh_size;
		return 0;
	}

	*out_buf = NULL;
	*out_sz  = 0;
	return 0;
}

/*
 * process_bpf_parsers_container - recursively process an ELF container, which holds a
 * batch of bpf parsers
 *
 * @elf_buf: ELF image buffer at this level
 * @elf_sz:  buffer length
 * @context: shared kexec parsing context
 * @depth:   current recursion depth (call with 1 for the top level)
 *
 *   1. a valid section names should be .bpf.1, .bpf.2, ... in order.
 *      They are different parser for the current layer.
 *   2. Only a .bpf.nested section is allowed for the internal level.
 *   3. At each level, stop trying at the first attempt where context->parsed becomes
 *      true, then try to load .bpf.nested to parse the internal layer
 *
 * Returns 0 on success, -EINVAL on any error.
 */
static int process_bpf_parsers_container(const char *elf_buf, size_t elf_sz,
				   struct kexec_context *context, int depth)
{
	struct bpf_parser_context *bpf;
	char *section_buf, *nested_buf;
	size_t section_sz;
	size_t nested_sz;
	/* .bpf.1 etc */
	char section_name[sizeof(KEXEC_ELF_BPF_PREFIX) + 1];
	bool found = false;
	int ret;
	int i;

	if (depth > KEXEC_ELF_BPF_MAX_DEPTH) {
		pr_err("kexec: ELF BPF nesting depth exceeds %d\n",
		       KEXEC_ELF_BPF_MAX_DEPTH);
		return -EINVAL;
	}

	ret = validate_elf_bpf_sections(elf_buf, elf_sz);
	if (ret)
		return ret;

	for (i = 1; i <= KEXEC_ELF_BPF_MAX_IDX && !found; i++) {
		snprintf(section_name, sizeof(section_name), ".bpf.%d", i);

		ret = elf_find_section(elf_buf, elf_sz, section_name,
				       &section_buf, &section_sz);
		if (ret)
			return ret;

		/* no section at this index means the sequence is exhausted */
		if (!section_buf)
			break;

		bpf = alloc_bpf_parser_context(kexec_buff_parser, context);
		if (!bpf)
			return -ENOMEM;

		ret = arm_bpf_prog(section_buf, section_sz);
		if (ret) {
			/* arm failed: no disarm needed, try next index */
			put_bpf_parser_context(bpf);
			pr_info("kexec: arm_bpf_prog failed for %s (depth %d), trying next\n",
				 section_name, depth);
			continue;
		}

		/*
		 * Give the BPF prog a clean slate so context->parsed reliably
		 * reflects whether *this* invocation succeeded.
		 */
		context->parsed = false;
		/* This is the hook point for bpf-prog */
		kexec_image_parser_anchor(context, (unsigned long)bpf);
		disarm_bpf_prog();
		/*
		 * bpf context has been released, so access to kexec_context
		 * through this BPF is no longer possible.
		 */
		put_bpf_parser_context(bpf);
		/* If the bpf-prog success, it flags by KEXEC_BPF_CMD_DONE */
		if (context->parsed) {
			found = true;
			/* Free the old parsing context, and reload the new */
			for (int i = 0; i < MAX_PARSING_BUF_NUM; i++) {
				if (!context->parsing_buf[i])
					break;
				vfree(context->parsing_buf[i]);
				context->parsing_buf[i] = NULL;
				context->parsing_buf_sz[i] = 0;
			}
			for (int i = 0; i < MAX_PARSING_BUF_NUM; i++) {
				if (!context->next_parsing_buf[i])
					break;
				context->parsing_buf[i] = context->next_parsing_buf[i];
				context->parsing_buf_sz[i] = context->next_parsing_buf_sz[i];
				context->next_parsing_buf[i] = NULL;
				context->next_parsing_buf_sz[i] = 0;
			}
		} else {
			/* Discard broken parsed result, then try next parser */
			for (int i = 0; i < MAX_PARSING_BUF_NUM; i++) {
				if (!context->next_parsing_buf[i])
					break;
				vfree(context->next_parsing_buf[i]);
				context->next_parsing_buf[i] = NULL;
				context->next_parsing_buf_sz[i] = 0;
			}
		}
	}

	if (!found) {
		pr_err("kexec: no BPF section succeeded at depth %d\n", depth);
		return -EINVAL;
	}

	/*
	 * A numbered section succeeded.  If .bpf.nested is present, the
	 * current context->kernel may still be in a container format that
	 * the next level of BPF progs knows how to unpack.
	 */
	ret = elf_find_section(elf_buf, elf_sz, KEXEC_ELF_BPF_NESTED,
			       &nested_buf, &nested_sz);
	if (ret)
		return ret;

	if (!nested_buf)
		return 0;

	context->parsed = false;
	return process_bpf_parsers_container(nested_buf, nested_sz, context,
				       depth + 1);
}

int decompose_kexec_image(struct kimage *image, int extended_fd)
{
	struct kexec_context ctx = { 0 };
	unsigned long parser_sz;
	char *parser_start;
	int ret = -EINVAL;

	if (extended_fd < 0)
		return ret;

	if (image->type != KEXEC_TYPE_CRASH)
		ctx.kdump = false;
	else
		ctx.kdump = true;

	parser_start = image->kernel_buf;
	parser_sz = image->kernel_buf_len;

	if (!validate_elf_bpf_sections(parser_start, parser_sz)) {

		/* It is right format, now check its signature */
		ret = verify_elf_sig(parser_start, parser_sz);
		if (ret)
			return ret;
		ret = kernel_read_file_from_fd(extended_fd,
						0,
						(void **)&ctx.parsing_buf[0],
						KEXEC_FILE_SIZE_MAX,
						NULL,
						0);
		if (ret < 0) {
			pr_err("Fail to read image container\n");
			return -EINVAL;
		}
		ctx.parsing_buf_sz[0] = ret;
		ret = process_bpf_parsers_container(parser_start, parser_sz, &ctx, 0);
		for (int i = 0; i < MAX_PARSING_BUF_NUM; i++) {
			if (!context->parsing_buf[i])
				break;
			vfree(context->parsing_buf[i]);
			context->parsing_buf[i] = NULL;
		}
		for (int i = 0; i < MAX_PARSING_BUF_NUM; i++) {
			if (!context->next_parsing_buf[i])
				break;
			vfree(context->next_parsing_buf[i]);
			context->next_parsing_buf[i] = NULL;
		}

		if (!ret) {
			char *p;

			/* Envelop should hold valid kernel, initrd, cmdline sections */
			if (!ctx.kernel || !ctx.initrd || !ctx.cmdline) {
				vfree(ctx.kernel);
				vfree(ctx.initrd);
				vfree(ctx.cmdline);
				return -EINVAL;
			}
			/*
			 * kimage_file_post_load_cleanup() calls kfree() to free
			 * cmdline
			 */
			p = kmalloc(ctx.cmdline_sz, GFP_KERNEL);
			if (!p) {
				vfree(ctx.kernel);
				vfree(ctx.initrd);
				vfree(ctx.cmdline);
				return -ENOMEM;
			}
			vfree(image->kernel_buf);
			image->kernel_buf = ctx.kernel;
			image->kernel_buf_len = ctx.kernel_sz;
			image->initrd_buf = ctx.initrd;
			image->initrd_buf_len = ctx.initrd_sz;
			memcpy(p, ctx.cmdline, ctx.cmdline_sz);
			image->cmdline_buf = p;
			image->cmdline_buf_len = ctx.cmdline_sz;
			vfree(ctx.cmdline);
			return 0;
		}
		else {
			return ret;
		}
	}

	return -EINVAL;
}
