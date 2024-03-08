#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tlsf.h"

#if 0
#define DPRINTF(format, ...) printf("%s(): " format, __func__, __VA_ARGS__)
#else
#define DPRINTF(format, ...)
#endif

// Global tlsf data, not thread safe but Solo5 is monothread so far :)
static tlsf_t memory = NULL;

// total memory currently in use, used/modified in tlsf.c
size_t memory_usage = 0;

void mm_init(uintptr_t start_addr, size_t size)
{
    uintptr_t start_heap = start_addr;
    // reserve 1MB for the stack
    uintptr_t end_heap = start_addr + size - 1024*1024;
    assert(end_heap > start_heap && "have enough memory");

    printf("Ocaml-Solo5: Version XXX\n");
    printf("Ocaml-Solo5:    heap @ (%p - %p)\n", (void*)start_heap, (void*)end_heap-1);
    printf("Ocaml-Solo5:   stack @ (%p - %p)\n", (void*)end_heap, (void*)(start_addr+size));

    memory = tlsf_create_with_pool((tlsf_t) start_heap, end_heap - start_heap);
    memory_usage = 0;
}

void *malloc(size_t size)
{
    void* ptr = tlsf_malloc(memory, size);
    DPRINTF("for %lu @%p, new memory usage = %lu\n", size, ptr, memory_usage);
    return ptr;
}

void free(void *ptr)
{
    tlsf_free(memory, ptr);
    DPRINTF("for %p, new memory usage = %lu\n", ptr, memory_usage);
}

void *calloc(size_t nmemb, size_t size)
{
    size_t total;
    // TODO: support other compiler/architectures...
    if (__builtin_mul_overflow(nmemb, size, &total))
    {
        errno = EINVAL;
        return NULL;
    }

    void *ptr = malloc(total);
    DPRINTF("for %lu @%p, new memory usage = %lu\n", total, ptr, memory_usage);

    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, total);
    return ptr;
}

void *realloc(void *ptr, size_t size)
{
    void* ret = tlsf_realloc(memory, ptr, size);
    DPRINTF("for %lu @%p, new memory usage = %lu\n", size, ptr, memory_usage);
    return ret;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    void *ptr = tlsf_memalign(memory, alignment, size);
    DPRINTF("for %lu @%p, new memory usage = %lu\n", size, ptr, memory_usage);

    if (ptr != NULL)
    {
        *memptr = ptr;
        return 0;   
    } else {
        return ENOMEM;    
    }
}

/*********************** STUBS (to remove?) ********************/

/* returns the total memory currently in use, needed for mirage-solo5/mirage-xen */
size_t malloc_memory_usage(void)
{
	return memory_usage;
}

struct mallinfo {
    int arena;     /* Non-mmapped space allocated (bytes) */
    int ordblks;   /* Number of free chunks */
    int smblks;    /* Number of free fastbin blocks */
    int hblks;     /* Number of mmapped regions */
    int hblkhd;    /* Space allocated in mmapped regions (bytes) */
    int usmblks;   /* Maximum total allocated space (bytes) */
    int fsmblks;   /* Space in freed fastbin blocks (bytes) */
    int uordblks;  /* Total allocated space (bytes) */
    int fordblks;  /* Total free space (bytes) */
    int keepcost;  /* Top-most, releasable space (bytes) */
};

struct mallinfo mallinfo(void)
{
	struct mallinfo m;
	memset(&m, 0, sizeof(struct mallinfo));
    // so far only uordblks is used (in mirage-solo5 and mirage-xen)
    m.uordblks = (int)memory_usage; // overflow could occurs with >2GB memory on 32b
	return m;
}

int malloc_trim(size_t pad)
{
    (void)pad; // unused argument
	return 0; // we won't ever return memory to the system :)
}

