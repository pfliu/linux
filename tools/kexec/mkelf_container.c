// SPDX-License-Identifier: GPL-2.0-only
/*
 * mkelf_container.c - pack PE files into an ELF container
 *
 * Each input file becomes a .pe.N section (1-indexed, raw bytes, no
 * padding).  If the file carries a security.ima xattr it is written
 * immediately after as a .ima section.
 *
 * Usage:
 *   mkelf_container -o <output.elf> <file1> [file2 ...]
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#define IMA_XATTR "security.ima"
#define IMA_XATTR_MAX 1024 /* upper bound for IMA sig blob */
#define SECTION_NAME_MAX 32

/* ------------------------------------------------------------------ */
/* In-memory representation of one ELF section before writing         */
/* ------------------------------------------------------------------ */

struct section {
	char name[SECTION_NAME_MAX]; /* name as it appears in shstrtab */
	uint8_t *data; /* owned heap buffer               */
	size_t size; /* exact byte count, no padding    */
};

struct section_list {
	struct section *items;
	size_t count;
	size_t cap;
};

static int seclist_push(struct section_list *sl, const char *name,
			uint8_t *data, size_t size)
{
	if (sl->count == sl->cap) {
		size_t new_cap = sl->cap ? sl->cap * 2 : 16;
		struct section *tmp =
			realloc(sl->items, new_cap * sizeof(*tmp));
		if (!tmp)
			return -ENOMEM;
		sl->items = tmp;
		sl->cap = new_cap;
	}
	struct section *s = &sl->items[sl->count++];
	strncpy(s->name, name, SECTION_NAME_MAX - 1);
	s->name[SECTION_NAME_MAX - 1] = '\0';
	s->data = data;
	s->size = size;
	return 0;
}

static void seclist_free(struct section_list *sl)
{
	for (size_t i = 0; i < sl->count; i++)
		free(sl->items[i].data);
	free(sl->items);
}

/* ------------------------------------------------------------------ */
/* File helpers                                                        */
/* ------------------------------------------------------------------ */

/*
 * read_file - read the entire contents of @path into a heap buffer.
 * Caller must free() the returned pointer.
 * Returns NULL on error (errno set).
 */
static uint8_t *read_file(const char *path, size_t *out_size)
{
	int fd;
	struct stat st;
	uint8_t *buf;
	ssize_t n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	buf = malloc(st.st_size);
	if (!buf) {
		close(fd);
		errno = ENOMEM;
		return NULL;
	}

	n = read(fd, buf, st.st_size);
	close(fd);

	if (n != st.st_size) {
		free(buf);
		errno = EIO;
		return NULL;
	}

	*out_size = (size_t)st.st_size;
	return buf;
}

/*
 * read_ima_xattr - read security.ima xattr from @path.
 * Returns a heap buffer with the raw xattr value, or NULL if absent /
 * on error.  Caller must free() the returned pointer.
 */
static uint8_t *read_ima_xattr(const char *path, size_t *out_size)
{
	uint8_t *buf;
	ssize_t sz;

	/* First call: probe the size */
	sz = getxattr(path, IMA_XATTR, NULL, 0);
	if (sz <= 0)
		return NULL;
	if (sz > IMA_XATTR_MAX) {
		fprintf(stderr,
			"warning: %s: security.ima xattr too large "
			"(%zd bytes), skipping\n",
			path, sz);
		return NULL;
	}

	buf = malloc(sz);
	if (!buf)
		return NULL;

	sz = getxattr(path, IMA_XATTR, buf, sz);
	if (sz <= 0) {
		free(buf);
		return NULL;
	}

	*out_size = (size_t)sz;
	return buf;
}

/* ------------------------------------------------------------------ */
/* String table builder                                                */
/* ------------------------------------------------------------------ */

struct strtab {
	uint8_t *data;
	size_t size;
	size_t cap;
};

/*
 * strtab_add - intern @str into @st.
 * Returns the byte offset of the string within the table, or (size_t)-1
 * on allocation failure.
 */
static size_t strtab_add(struct strtab *st, const char *str)
{
	size_t slen = strlen(str) + 1; /* include NUL */
	size_t off = st->size;
	size_t need = st->size + slen;

	if (need > st->cap) {
		size_t new_cap = st->cap ? st->cap * 2 : 256;
		while (new_cap < need)
			new_cap *= 2;
		uint8_t *tmp = realloc(st->data, new_cap);
		if (!tmp)
			return (size_t)-1;
		st->data = tmp;
		st->cap = new_cap;
	}

	memcpy(st->data + st->size, str, slen);
	st->size = need;
	return off;
}

/* ------------------------------------------------------------------ */
/* ELF writer                                                          */
/* ------------------------------------------------------------------ */

/*
 * write_elf - serialise @sl as an ELF64 container to @out_path.
 *
 * Layout:
 *   [ Elf64_Ehdr ]
 *   [ section data 0 .. N-1 ]  (exact sizes, no inter-section padding)
 *   [ shstrtab data          ]
 *   [ Elf64_Shdr table       ]
 *
 * sh_addralign is set to 1 for every data section so that no tool
 * inserts implicit padding when re-reading the file.
 */
static int write_elf(const char *out_path, struct section_list *sl)
{
	/*
         * Total section count = null + sl->count + shstrtab
         */
	size_t num_shdrs = 1 + sl->count + 1;
	Elf64_Shdr *shdrs = calloc(num_shdrs, sizeof(*shdrs));
	if (!shdrs)
		return -ENOMEM;

	/* Build section name string table */
	struct strtab shstrtab = { 0 };

	/* Null entry at offset 0 */
	if (strtab_add(&shstrtab, "") == (size_t)-1)
		goto oom;

	/* Collect name offsets for each data section */
	size_t *name_offs = calloc(sl->count, sizeof(*name_offs));
	if (!name_offs)
		goto oom;

	for (size_t i = 0; i < sl->count; i++) {
		name_offs[i] = strtab_add(&shstrtab, sl->items[i].name);
		if (name_offs[i] == (size_t)-1)
			goto oom;
	}

	size_t shstrtab_name_off = strtab_add(&shstrtab, ".shstrtab");
	if (shstrtab_name_off == (size_t)-1)
		goto oom;

	/* Open output file */
	int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror(out_path);
		free(name_offs);
		free(shstrtab.data);
		free(shdrs);
		return -errno;
	}

	/* --- ELF header placeholder (filled in later) --- */
	Elf64_Ehdr ehdr = { 0 };
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
	ehdr.e_type = ET_REL;
	ehdr.e_machine = EM_NONE;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_shentsize = sizeof(Elf64_Shdr);
	/* e_shoff and e_shnum filled in after we know offsets */

	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		perror("write ehdr");
		goto io_err;
	}

	off_t pos = sizeof(ehdr);

	/* --- Section data --- */

	/* shdr[0]: null section (all zeros, already) */

	for (size_t i = 0; i < sl->count; i++) {
		struct section *s = &sl->items[i];
		Elf64_Shdr *shdr = &shdrs[1 + i];

		shdr->sh_name = (Elf64_Word)name_offs[i];
		shdr->sh_type = SHT_PROGBITS;
		shdr->sh_flags = 0;
		shdr->sh_addr = 0;
		shdr->sh_offset = (Elf64_Off)pos;
		shdr->sh_size = s->size;
		shdr->sh_link = 0;
		shdr->sh_info = 0;
		shdr->sh_addralign = 1; /* no padding */
		shdr->sh_entsize = 0;

		if (s->size > 0) {
			ssize_t w = write(fd, s->data, s->size);
			if (w != (ssize_t)s->size) {
				perror("write section data");
				goto io_err;
			}
			pos += s->size;
		}
	}

	/* --- shstrtab --- */
	size_t shstrtab_idx = num_shdrs - 1;
	Elf64_Shdr *shstrtab_shdr = &shdrs[shstrtab_idx];
	shstrtab_shdr->sh_name = (Elf64_Word)shstrtab_name_off;
	shstrtab_shdr->sh_type = SHT_STRTAB;
	shstrtab_shdr->sh_flags = 0;
	shstrtab_shdr->sh_offset = (Elf64_Off)pos;
	shstrtab_shdr->sh_size = shstrtab.size;
	shstrtab_shdr->sh_addralign = 1;

	if (write(fd, shstrtab.data, shstrtab.size) != (ssize_t)shstrtab.size) {
		perror("write shstrtab");
		goto io_err;
	}
	pos += shstrtab.size;

	/* --- Section header table --- */
	/*
         * ELF64 requires e_shoff to be 8-byte aligned because Elf64_Shdr
         * contains 64-bit fields.  Insert minimal zero padding if needed.
         * This padding is between shstrtab and the shdr table; it is not
         * part of any section's data and does not affect sh_size values.
         */
	if (pos % 8 != 0) {
		uint8_t pad[8] = { 0 };
		size_t align = 8 - (pos % 8);

		if (write(fd, pad, align) != (ssize_t)align) {
			perror("write shoff alignment padding");
			goto io_err;
		}
		pos += align;
	}

	off_t shoff = pos;

	ssize_t shdr_bytes = num_shdrs * sizeof(Elf64_Shdr);
	if (write(fd, shdrs, shdr_bytes) != shdr_bytes) {
		perror("write shdrs");
		goto io_err;
	}

	/* --- Fix up ELF header --- */
	ehdr.e_shoff = (Elf64_Off)shoff;
	ehdr.e_shnum = (Elf64_Half)num_shdrs;
	ehdr.e_shstrndx = (Elf64_Half)shstrtab_idx;

	if (lseek(fd, 0, SEEK_SET) != 0) {
		perror("lseek");
		goto io_err;
	}
	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		perror("rewrite ehdr");
		goto io_err;
	}

	close(fd);
	free(name_offs);
	free(shstrtab.data);
	free(shdrs);
	return 0;

oom:
	fprintf(stderr, "out of memory\n");
	free(name_offs);
	free(shstrtab.data);
	free(shdrs);
	return -ENOMEM;

io_err:
	close(fd);
	unlink(out_path);
	free(name_offs);
	free(shstrtab.data);
	free(shdrs);
	return -EIO;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s -o <output.elf> <file1> [file2 ...]\n",
		prog);
}

int main(int argc, char *argv[])
{
	const char *out_path = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "o:")) != -1) {
		switch (opt) {
		case 'o':
			out_path = optarg;
			break;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (!out_path) {
		fprintf(stderr, "error: -o <output> is required\n");
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (optind >= argc) {
		fprintf(stderr, "error: at least one input file required\n");
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	struct section_list sl = { 0 };
	int pe_index = 1;
	int ret = 0;

	for (int i = optind; i < argc; i++, pe_index++) {
		const char *path = argv[i];
		size_t pe_size = 0;
		size_t ima_size = 0;
		uint8_t *pe_data = NULL;
		uint8_t *ima_data = NULL;

		/* Read PE file content */
		pe_data = read_file(path, &pe_size);
		if (!pe_data) {
			fprintf(stderr, "error: cannot read %s: %s\n", path,
				strerror(errno));
			ret = EXIT_FAILURE;
			goto out;
		}

		/* Build section name ".pe.N" */
		char sec_name[SECTION_NAME_MAX];
		snprintf(sec_name, sizeof(sec_name), ".pe.%d", pe_index);

		if (seclist_push(&sl, sec_name, pe_data, pe_size) < 0) {
			fprintf(stderr, "error: out of memory\n");
			free(pe_data);
			ret = EXIT_FAILURE;
			goto out;
		}
		/* pe_data ownership transferred to seclist */

		/* Optionally read security.ima xattr */
		ima_data = read_ima_xattr(path, &ima_size);
		if (ima_data) {
			if (seclist_push(&sl, ".ima", ima_data, ima_size) < 0) {
				fprintf(stderr, "error: out of memory\n");
				free(ima_data);
				ret = EXIT_FAILURE;
				goto out;
			}
			/* ima_data ownership transferred to seclist */
			printf("%s: added .pe.%d + .ima (%zu + %zu bytes)\n",
			       path, pe_index - 1 + 1, pe_size, ima_size);
		} else {
			printf("%s: added .pe.%d (%zu bytes, no IMA xattr)\n",
			       path, pe_index - 1 + 1, pe_size);
		}
	}

	ret = write_elf(out_path, &sl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to write %s: %s\n", out_path,
			strerror(-ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	printf("wrote %s (%zu sections)\n", out_path, sl.count);
	ret = EXIT_SUCCESS;

out:
	seclist_free(&sl);
	return ret;
}
