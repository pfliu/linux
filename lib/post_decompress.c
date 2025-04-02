
/* Max decompressed size is capped at 512M */
static unsigned int max_uncompressed_buf_sz = (1 << 29);
#define CHUNK_SIZE (1 << 23)
#define CHUNK_PAGES (CHUNK_SIZE / PAGE_SIZE)

struct decompress_mem_allocator {
	struct page **pages;
	unsigned int total_pages;
	unsigned int max_pages;

	void *chunk_vaddr;
	unsigned long chunk_offset;
	unsigned long total_written;
};

static DEFINE_MUTEX(dcmpr_lock);
static struct decompress_mem_allocator dcmpr_allocator;

static void *allocate_chunk_memory(void)
{
	struct decompress_mem_allocator *a = &dcmpr_allocator;
	unsigned int base = a->total_pages;
	void *vaddr;
	int i;

	if (base + CHUNK_PAGES > a->max_pages)
		return NULL;

	for (i = 0; i < CHUNK_PAGES; i++) {
		a->pages[base + i] = alloc_page(GFP_KERNEL | __GFP_ACCOUNT);
		if (!a->pages[base + i]) {
			while (--i >= 0)
				__free_page(a->pages[base + i]);
			return NULL;
		}
	}

	if (a->chunk_vaddr)
		vunmap(a->chunk_vaddr);

	vaddr = vmap(&a->pages[base], CHUNK_PAGES, VM_MAP, PAGE_KERNEL);
	if (!vaddr) {
		for (i = 0; i < CHUNK_PAGES; i++)
			__free_page(a->pages[base + i]);
		return NULL;
	}

	a->total_pages += CHUNK_PAGES;
	a->chunk_vaddr = vaddr;
	a->chunk_offset = 0;
	return vaddr;
}

static int merge_decompressed_data(struct decompress_mem_allocator *a,
				   char **out, unsigned long *size)
{
	void *merged;

	if (a->chunk_vaddr) {
		vunmap(a->chunk_vaddr);
		a->chunk_vaddr = NULL;
	}

	merged = vmap(a->pages, a->total_pages, VM_MAP, PAGE_KERNEL);
	if (!merged)
		return -ENOMEM;

	*out = merged;
	*size = a->total_written;
	return 0;
}

static int decompress_mem_allocator_init(struct decompress_mem_allocator *a)
{
	unsigned int max_pages = max_uncompressed_buf_sz / PAGE_SIZE;

	a->pages = kvcalloc(max_pages, sizeof(struct page *), GFP_KERNEL);
	if (!a->pages)
		return -ENOMEM;

	a->max_pages = max_pages;
	a->total_pages = 0;
	a->chunk_vaddr = NULL;
	a->chunk_offset = 0;
	a->total_written = 0;

	if (!allocate_chunk_memory()) {
		kvfree(a->pages);
		return -ENOMEM;
	}
	return 0;
}

static void decompress_mem_allocator_fini(struct decompress_mem_allocator *a)
{
	unsigned int i;

	if (a->chunk_vaddr) {
		vunmap(a->chunk_vaddr);
		a->chunk_vaddr = NULL;
	}
	for (i = 0; i < a->total_pages; i++) {
		if (a->pages[i])
			__free_page(a->pages[i]);
	}
	kvfree(a->pages);
}

static long flush(void *buf, unsigned long len)
{
	struct decompress_mem_allocator *a = &dcmpr_allocator;
	unsigned long free, copied = 0;

	if (unlikely(len > CHUNK_SIZE)) {
		pr_info("Chunk size is too small to hold decompressed data\n");
		return -1;
	}

	free = CHUNK_SIZE - a->chunk_offset;
	if (free < len) {
		memcpy(a->chunk_vaddr + a->chunk_offset, buf, free);
		copied += free;
		a->total_written += free;
		buf += free;
		len -= free;

		if (!allocate_chunk_memory()) {
			pr_info("Decompression runs out of memory\n");
			return -1;
		}
	}

	memcpy(a->chunk_vaddr + a->chunk_offset, buf, len);
	copied += len;
	a->chunk_offset += len;
	a->total_written += len;
	return copied;
}

static void decompress_error(char *msg)
{
	pr_err("kexec: decompression error: %s\n", msg);
}

int post_boot_decompress(char *compressed_data, int size,
		char **out_buf, unsigned long *out_sz)
{
	struct decompress_mem_allocator *a;
	decompress_fn decompressor;
	const char *name;
	int ret;

	mutex_lock(&dcmpr_lock);
	a = &dcmpr_allocator;
	ret = decompress_mem_allocator_init(a, CHUNK_SIZE);
	if (ret < 0) {
		mutex_unlock(&dcmpr_lock);
		return ret;
	}
	decompressor = decompress_method(compressed_data, size, &name);
	if (!decompressor) {
		pr_err("Can not find decompress method\n");
		ret = -1;
		goto err;
	}
	pr_debug("Find decompressing method: %s, compressed sz:0x%x\n",
			name, size);
	ret = decompressor(compressed_data, size, NULL, flush,
				NULL, NULL, decompress_error);
	if (!!ret)
		goto err;
	ret = merge_decompressed_data(a, out_buf, out_sz);

err:
	decompress_mem_allocator_fini(a);
	mutex_unlock(&dcmpr_lock);

	return ret;
}
