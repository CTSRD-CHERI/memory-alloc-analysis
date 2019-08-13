#include <assert.h>
#include <stdlib.h>
#include <err.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/queue.h>

#include "mapd_aspace.h"


#define PAGE_ALIGN_DOWN(x)   \
        (((x) >> PAGE_SHIFT) << PAGE_SHIFT)
#define PAGE_ALIGN_UP(x)   \
        PAGE_ALIGN_DOWN((x) + PAGE_SIZE - 1)


struct mapd_aspace {
	void *as_start;
	size_t as_size;
	STAILQ_ENTRY(mapd_aspace) next;
};

static STAILQ_HEAD(mapd_aspaces, mapd_aspace) mapd_aspaces =
                                         STAILQ_HEAD_INITIALIZER(mapd_aspaces);


static struct mapd_aspace *
mapd_aspace_alloc(size_t size) {
	void *m;
	struct mapd_aspace *mas;

	mas = malloc(sizeof(struct mapd_aspace));
	if (!mas)
		err(1, "mapd_aspace_alloc()");
	m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE |
	         MAP_ALIGNED(PAGE_SHIFT), -1, 0);
	if (m == MAP_FAILED)
		err(1, "mapd_aspace_alloc(size=%lu)", size);

	mas->as_start = m;
	mas->as_size = size;
	return mas;
}

static void
mapd_aspace_dealloc(struct mapd_aspace *mas) {
	int ret;
	ret = munmap(mas->as_start, mas->as_size);
	if (ret)
		err(1, "mapd_aspace_dealloc({->as_start = %p; ->as_size = %lu})",
		    mas->as_start, mas->as_size);
	free(mas);
}

static void
mapd_aspace_shrink(struct mapd_aspace *mas, size_t _amount) {
	int ret;
	/* Page-align down to satisfy munmap() below. */
	size_t size_new = PAGE_ALIGN_DOWN(mas->as_size - _amount);
	assert(size_new < mas->as_size);

	ret = munmap(mas->as_start + size_new, mas->as_size - size_new);
	if (ret)
		err(1, "mapd_aspace_shrink({->as_start = %p; ->as_size = %lu}, %ld (was %lu))",
		    mas->as_start, mas->as_size, mas->as_size - size_new, _amount);

	mas->as_size = size_new;
}


size_t
mapd_aspace_add(const size_t _amount) {
	/* Page-align up the size to provide guarantee needed below. */
	struct mapd_aspace *m = mapd_aspace_alloc(PAGE_ALIGN_UP(_amount));
	void *live_cap = m;

	/*
	 * Cap-dirty all mapped pages.
	 * Write a capability at the beginning and, paranoically, at the end of the
	 * each underlying page.  The mapped aspace is guaranteed to include pages'
	 * (PAGE_ALIGN_UP above).
	 */
	for (void *p = m->as_start, *mend = m->as_start + m->as_size; p < mend;
	     p += PAGE_SIZE) {
		void *pend = p + PAGE_SIZE;
		((volatile void**)p)[0] = live_cap;
		((volatile void**)pend)[-1] = live_cap;
	}

	STAILQ_INSERT_TAIL(&mapd_aspaces, m, next);

	return m->as_size;
}

size_t
mapd_aspace_remove(const size_t amount) {
	struct mapd_aspace *tmp;
	long int amount_rem = amount;

	while (amount_rem > 0 && !STAILQ_EMPTY(&mapd_aspaces)) {
		struct mapd_aspace *m = STAILQ_FIRST(&mapd_aspaces);
		if (m->as_size <= amount_rem) {
			amount_rem -= m->as_size;
			STAILQ_REMOVE_HEAD(&mapd_aspaces, next);
			mapd_aspace_dealloc(m);
		} else {
			size_t as_size_prev = m->as_size;
			mapd_aspace_shrink(m, amount_rem);
			size_t shrink_actual = as_size_prev - m->as_size;
			amount_rem -= shrink_actual;
		}
	}

	return amount - amount_rem;
}
