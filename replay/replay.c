/*
 * Replay a trace to an actual malloc.
 *
 * Build with, e.g., on (Free)BSD:
 *
 *   clang -g -o replay replay.c
 *
 * or on Linux with libbsd installed:
 *
 *   clang $(pkg-config --cflags --libs libbsd-overlay) -g -o replay replay.c
 *
 * (The BSD sys/tree.h is used to give us a sufficiently friendly
 * associative data structure.  Why this isn't ISO or POSIX or SUS, I don't
 * know.)
 */

    // Debug printfs
#define replay_dprintf(...) printf(__VA_ARGS__)
    // Verbose printfs
#define replay_vprintf(...) printf(__VA_ARGS__)

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdalign.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/tree.h>

#define MAX(a,b) ((a) > (b) ? (a) : (b))

struct alloc {
    RB_ENTRY(alloc) linkage;
    uint64_t vaddr;
};

static int
alloc_cmp(struct alloc *a, struct alloc *b) {
    return b->vaddr - a->vaddr;
}

RB_HEAD(alloc_entries, alloc) allocs = RB_INITIALIZER(&allocs);

RB_PROTOTYPE(alloc_entries, alloc, linkage, alloc_cmp);
RB_GENERATE(alloc_entries, alloc, linkage, alloc_cmp);

static unsigned long long
estrtoull(const char *b, int base, int *err)
{
    char *endp = NULL;
    errno = 0;
    unsigned long long res = strtoull(b, &endp, base);
    if ((*endp != '\0') || ((res == ULLONG_MAX) && (errno != 0))) {
        *err = 1;
        return ULLONG_MAX;
    }
    *err = 0;
    return res;
}

static struct alloc *
find_alloc_for_vaddr(uint64_t vaddr) {
    struct alloc find = { .vaddr = vaddr };
    struct alloc *a = RB_FIND(alloc_entries, &allocs, &find);
    if (a == NULL) {
        fprintf(stderr,
                "No active allocation for node at 0x%" PRIx64 "\n",
                vaddr);
        abort();
    }

    return a;
}

static void
insert_alloc_for_vaddr(struct alloc *a, uint64_t vaddr) {
    a->vaddr = vaddr;

    struct alloc *b = RB_INSERT(alloc_entries, &allocs, a);
    if (b != NULL) {
        fprintf(stderr,
                "Conflicting active allocations at 0x%" PRIx64 "\n",
                vaddr);
        abort();
    }
}

static int
do_trace_line(FILE *f) {
    char lbuf[16384];

    uint64_t ts;
    uint64_t tid;
    uint64_t res;
    char cmd[32];
    char args[128];

    char *b = fgets(lbuf, sizeof lbuf, f);
    if (b != lbuf) {
        return 1;
    }

    int n = sscanf(lbuf,
        "call-trace "       // header (ignored)
        "%" SCNu64 " "      // timestamp
        "%*[^\t] "          // callstack (ignored, space-separated)
        "%" SCNu64 " "      // tid
        "%31s "             // call name
        "%127[^\t] "        // arguments (space-separated)
        "%" SCNx64 " "      // result (hex)
        "%*[^\t] "          // alloc-stack (ignored, space-separated)
        "%*s"               // cpu-time (ignored)
        "%*[\r\n]"          // newline (ignored, but must match)
        , &ts, &tid, cmd, args, &res);
    if (n == 5) {
        replay_dprintf("OK: %" PRIu64 " %" PRIu64 " %s %s => 0x%" PRIx64 "\n",
            ts, tid, cmd, args, res);
    } else {
        res = 0;
    
        n = sscanf(lbuf,
            "call-trace "       // header (ignored)
            "%" SCNu64 " "      // timestamp
            "%*[^\t] "          // callstack (ignored, space-separated)
            "%" SCNu64 " "      // tid
            "%31s "             // call name
            "%127[^\t] "        // arguments (space-separated)
            "%*[^\t] "          // alloc-stack (ignored, space-separated)
            "%*s"               // cpu-time (ignored)
            "%*[\r\n]"          // newline (ignored, but must match)
            , &ts, &tid, cmd, args);

        if (n == 4) {
            replay_dprintf("OK: %" PRIu64 " %" PRIu64 " %s %s => 0 \n",
                ts, tid, cmd, args);
        } else if (feof(f)) {
            return 1;
        } else {
            replay_vprintf("SKIP LINE: %s", lbuf);
            return 0;
        }
    }

    if (!strcmp(cmd, "free")) {
        /* Find the corresponding allocation and remove it */
        int err = 0;
        uint64_t vaddr = estrtoull(args, 16, &err);
        if (err) {
            fprintf(stderr,
                "Bad free() argument \"%s\" at ts=%" PRIu64 "\n",
                args, ts);
            abort();
        }
        struct alloc *f = find_alloc_for_vaddr(vaddr);
        RB_REMOVE(alloc_entries, &allocs, f);
        free(f);
    } else if (!strcmp(cmd, "malloc")) {
        int err = 0;
        size_t sz = estrtoull(args, 10, &err);
        if (err) {
            fprintf(stderr,
                "Bad malloc() argument \"%s\" at ts=%" PRIu64 "\n",
                args, ts);
            abort();
        }
        struct alloc *f = malloc(MAX(sz, sizeof (struct alloc)));
        if (f == NULL) {
            fprintf(stderr, "OOM at ts=%" PRIu64 "\n", ts);
            abort();
        }
        insert_alloc_for_vaddr(f, res);
    } else if (!strcmp(cmd, "calloc")) {
        int err = 0;
        char *sp = strchr(args, ' ');
        if (sp == NULL) {
bad_calloc: 
            fprintf(stderr,
                "Bad calloc args: \"%s\" at ts=%" PRIu64 "\n",
                args, ts);
            abort();
        }

        *sp = '\0';

        size_t n = estrtoull(args, 10, &err);
        if (err) {
            goto bad_calloc;
        }

        size_t s = estrtoull(sp + 1, 10, &err);
        if (err) {
            goto bad_calloc;
        }

        if (n * s < sizeof (struct alloc)) {
            n = 1;
            s = sizeof (struct alloc);
        }

        struct alloc *f = calloc(n, s);
        if (f == NULL) {
            fprintf(stderr, "OOM at ts=%" PRIu64 "\n", ts);
            abort();
        }
        insert_alloc_for_vaddr(f, res);

    } else if (!strcmp(cmd, "realloc")) {
        int err = 0;

        char *sp = strchr(args, ' ');
        if (sp == NULL) {
bad_realloc: 
            fprintf(stderr,
                "Bad realloc args: \"%s\" at ts=%" PRIu64 "\n",
                args, ts);
            abort();
        }

        *sp = '\0';

        uint64_t vaddr = estrtoull(args, 16, &err);
        if (err) {
            goto bad_realloc;
        }

        size_t sz = estrtoull(sp+1, 10, &err);
        if (err) {
            goto bad_realloc;
        }

        struct alloc *f = find_alloc_for_vaddr(vaddr);

        if (vaddr != 0) {
            RB_REMOVE(alloc_entries, &allocs, f);
        }

        struct alloc *g = realloc(f, MAX(sz, sizeof (struct alloc)));

        if ((sz != 0) && (g == NULL)) {
            fprintf(stderr, "OOM at ts=%" PRIu64 "\n", ts);
            abort();
        }

        if ((g != NULL) && (res != 0)) {
            insert_alloc_for_vaddr(g, res);
        }

    } else if (!strcmp(cmd, "posix_memalign")) {
        /*
         * This one deviates a little bit from its C prototype: the
         * outpointer is given to us as the return value.
         */

        int err = 0;

        char *sp = strchr(args, ' ');
        if (sp == NULL) {
bad_memalign: 
            fprintf(stderr,
                "Bad posix_memalign args: \"%s\" at ts=%" PRIu64 "\n",
                args, ts);
            abort();
        }

        *sp = '\0';

        size_t align = estrtoull(args, 10, &err);
        if (err) {
            goto bad_memalign;
        }

        size_t sz = estrtoull(sp+1, 10, &err);
        if (err) {
            goto bad_memalign;
        }

        align = MAX(align, alignof(struct alloc));
        sz    = MAX(sz   , sizeof (struct alloc));

        void *f;
        err = posix_memalign(&f, align, sz);
        if (err) {
            fprintf(stderr, "OOM (err=%d) at ts=%" PRIu64 "\n", err, ts);
            abort();
        }

        insert_alloc_for_vaddr(f, res);

#if 0
    // Not often encountered in traces, but we could
    } else if (!strcmp(cmd, "aligned_alloc")) {

#endif

    } else if (!strcmp(cmd, "mmap")) {
        /* Suppressed */
        ;

    } else if (!strcmp(cmd, "munmap")) {
        /* Suppressed */
        ;

    } else {
        replay_vprintf("SKIP CMD: %s\n", cmd);
    }

    return 0;
}

int
main(int argc, char **argv) {

    while (do_trace_line(stdin) == 0) { ; }

}
