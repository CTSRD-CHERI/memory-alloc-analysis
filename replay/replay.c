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
#ifdef DEBUG
#define replay_dprintf(...) do { printf(__VA_ARGS__) } while(0)
#else
#define replay_dprintf(...) do { ; } while(0)
#endif
    // Verbose printfs
#define replay_vprintf(...) printf(__VA_ARGS__)

#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/tree.h>
#include <unistd.h>

#include "mapd_aspace.h"

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
        exit(1);
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
        exit(1);
    }
}


static char line[16384];
static int line_no = 0;


typedef struct _spec_field {
    const char *n;
    int i;
} _spec_field_t;

static struct call_trace_spec {
    _spec_field_t ts;
    _spec_field_t tid;
    _spec_field_t name;
    _spec_field_t args;
    _spec_field_t res;
} trace_spec;

static struct aspace_sample_spec {
    _spec_field_t ts;
    _spec_field_t aspace_size;
    _spec_field_t aspace_capdirty_size;
} aspace_sample_spec;

static bool trace_spec_parsed = false;
static bool aspace_sample_spec_parsed = false;

static void
trace_spec_init(void) {
    static const struct call_trace_spec cts = {{.n = "timestamp", .i = 0},
                                               {.n = "tid",       .i = 0},
                                               {.n = "name",      .i = 0},
                                               {.n = "args",      .i = 0},
                                               {.n = "result",    .i = 0},
                                              };
    trace_spec = cts;
    trace_spec_parsed = false;
}

static void
aspace_sample_spec_init(void) {
    static const struct aspace_sample_spec as =
                                              {{.n = "timestamp",       .i = 0},
                                               {.n = "addr-space-size", .i = 0},
                                               {.n = "sweep-amount",    .i = 0},
                                              };
    aspace_sample_spec = as;
    aspace_sample_spec_parsed = false;
}

#define INIT_MISSING(...) do { \
    char missing[512] = {[0] = '\0'};   \
    int missing_strlen = 0;             \
    int missing_strlen_max = sizeof(missing) - 1;

#define UNINIT_MISSING(...)    } while(0)

#define APPEND_TO_MISSING(str) do { \
    int __len = strlen(str);     \
    if (missing_strlen + 1 + __len < missing_strlen_max) {   \
        missing[missing_strlen++] = ' ';           \
        missing[missing_strlen] = '\0';            \
        strcat(missing, str);  \
        missing_strlen += __len; \
    } \
    } while (0)

#define CHECK_SPEC_FIELD_MISSING(spec_field) do {    \
    if (!spec_field.i) {                     \
        APPEND_TO_MISSING(spec_field.n);     \
    } \
    } while(0)

static int
do_call_trace_spec(char *lbuf) {
    char *rest = lbuf;
    const char *field;
    int ret;

    trace_spec_init();

    (void)strsep(&rest, "\t\n");
    for(int i = 1; (field = strsep(&rest, "\t\n")) != NULL; i++) {
        if (strstr(field, trace_spec.ts.n) == field)
            trace_spec.ts.i = i;
        else if (strstr(field, trace_spec.tid.n) == field)
            trace_spec.tid.i = i;
        else if (strstr(field, trace_spec.name.n) == field)
            trace_spec.name.i = i;
        else if (strstr(field, trace_spec.args.n) == field)
            trace_spec.args.i = i;
        else if (strstr(field, trace_spec.res.n) == field)
            trace_spec.res.i = i;
    }

    INIT_MISSING();
    CHECK_SPEC_FIELD_MISSING(trace_spec.ts);
    CHECK_SPEC_FIELD_MISSING(trace_spec.tid);
    CHECK_SPEC_FIELD_MISSING(trace_spec.name);
    CHECK_SPEC_FIELD_MISSING(trace_spec.args);
    CHECK_SPEC_FIELD_MISSING(trace_spec.res);

    if (missing_strlen > 0) {
        fprintf(stderr, "call-trace specification is missing field%s"
                  "\n\tat line %d: '%s'\n", missing, line_no, line);
        return 1;
    }
    UNINIT_MISSING();

    trace_spec_parsed = true;
    return 0;
}

static int
do_call_trace(char *lbuf) {
    static const int FIELDS = sizeof(struct call_trace_spec) / sizeof(_spec_field_t);

    uint64_t ts;
    uint64_t tid;
    const char *cmd;
    const char *args;
    const char *res_str;

    if (!trace_spec_parsed) {
        fprintf(stderr, "Missing specification '@record-type:call-trace'\n");
        exit(1);
    }

    int i = 0, fields = 0;
    for(char *field, *rest = lbuf; (field = strsep(&rest, "\t\n")) != NULL; i++) {
        if (trace_spec.ts.i == i) {
            int err = 0;
            char *ts_str = field;
            ts = estrtoull(ts_str, 10, &err);
            if (err) {
                fprintf(stderr, "Bad timestamp '%s'"
                        "\nat line %d: '%s'\n", ts_str, line_no, line);
                exit(1);
            }
            fields++;
        } else if (trace_spec.tid.i == i) {
            int err = 0;
            char *tid_str = field;
            tid = estrtoull(tid_str, 10, &err);
            if (err) {
                fprintf(stderr, "Bad tid '%s'"
                        "\nat line %d: '%s'\n", tid_str, line_no, line);
                exit(1);
            }
            fields++;
        } else if (trace_spec.name.i == i) {
            cmd = field;
            fields++;
        } else if (trace_spec.args.i == i) {
            args = field;
            fields++;
        } else if (trace_spec.res.i == i) {
            res_str = field;
            fields++;
        }
        if (fields == FIELDS) break;
    }

    if (fields < FIELDS) {
        fprintf(stderr, "Bad 'call-trace' record line with only %d out of %d "
                "required fields"
                "\n\tat line %d: '%s'\n", fields, FIELDS, line_no, line);
        return 1;
    }
    if (strlen(res_str) > 0)
        replay_dprintf("OK: %" PRIu64 " %" PRIu64 " %s %s => %s\n",
            ts, tid, cmd, args, res_str);
    else
        replay_dprintf("OK: %" PRIu64 " %" PRIu64 " %s %s\n",
            ts, tid, cmd, args);

    if (!strcmp(cmd, "free")) {
        /* Find the corresponding allocation and remove it */
        int err = 0;
        uint64_t vaddr = estrtoull(args, 16, &err);

        if (err) {
            fprintf(stderr,
                "Bad free() argument \"%s\" at ts=%" PRIu64 "\n",
                args, ts);
            exit(1);
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
            exit(1);
        }
        uint64_t res = estrtoull(res_str, 16, &err);
        if (err) {
            fprintf(stderr,
                "Bad malloc() result \"%s\" at ts=%" PRIu64 "\n",
                res_str, ts);
            exit(1);
        }

        struct alloc *f = malloc(MAX(sz, sizeof (struct alloc)));
        if (f == NULL) {
            fprintf(stderr, "OOM at ts=%" PRIu64 "\n", ts);
            exit(1);
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
            exit(1);
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
        uint64_t res = estrtoull(res_str, 16, &err);
        if (err) {
            fprintf(stderr,
                "Bad calloc() result \"%s\" at ts=%" PRIu64 "\n",
                res_str, ts);
            exit(1);
        }

        struct alloc *f = calloc(n, s);
        if (f == NULL) {
            fprintf(stderr, "OOM at ts=%" PRIu64 "\n", ts);
            exit(1);
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
            exit(1);
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
        uint64_t res = estrtoull(res_str, 16, &err);
        if (err) {
            fprintf(stderr,
                "Bad realloc() result \"%s\" at ts=%" PRIu64 "\n",
                res_str, ts);
            exit(1);
        }

        struct alloc *f = find_alloc_for_vaddr(vaddr);

        if (vaddr != 0) {
            RB_REMOVE(alloc_entries, &allocs, f);
        }

        struct alloc *g = realloc(f, MAX(sz, sizeof (struct alloc)));

        if ((sz != 0) && (g == NULL)) {
            fprintf(stderr, "OOM at ts=%" PRIu64 "\n", ts);
            exit(1);
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
            exit(1);
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
        uint64_t res = estrtoull(res_str, 16, &err);
        if (err) {
            fprintf(stderr,
                "Bad posix_memalign result: \"%s\" at ts=%" PRIu64 "\n",
                res_str, ts);
            exit(1);
        }

        align = MAX(align, alignof(struct alloc));
        sz    = MAX(sz   , sizeof (struct alloc));

        void *f;
        err = posix_memalign(&f, align, sz);
        if (err) {
            fprintf(stderr, "OOM (err=%d) at ts=%" PRIu64 "\n", err, ts);
            exit(1);
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
        replay_vprintf("SKIP CMD '%s'"
                       "\n\tat line %d: '%s'\n", cmd, line_no, line);
    }

    return 0;
}

int
do_aspace_sample_spec(char *lbuf)
{
    char *rest = lbuf;
    const char *field;

    aspace_sample_spec_init();

    (void)strsep(&rest, "\t\n");
    for (int i = 1; (field = strsep(&rest, "\t\n")) != NULL; i++) {
        if (strstr(field, aspace_sample_spec.ts.n) == field)
            aspace_sample_spec.ts.i = i;
        else if (strstr(field, aspace_sample_spec.aspace_size.n) == field)
            aspace_sample_spec.aspace_size.i = i;
        else if (strstr(field, aspace_sample_spec.aspace_capdirty_size.n) == field)
            aspace_sample_spec.aspace_capdirty_size.i = i;
    }

    INIT_MISSING();
    CHECK_SPEC_FIELD_MISSING(aspace_sample_spec.ts);
    CHECK_SPEC_FIELD_MISSING(aspace_sample_spec.aspace_size);
    CHECK_SPEC_FIELD_MISSING(aspace_sample_spec.aspace_capdirty_size);

    if (missing_strlen > 0) {
        fprintf(stderr, "call-trace specification is missing field%s"
                  "\n\tat line %d: '%s'\n", missing, line_no, line);
        return 1;
    }
    UNINIT_MISSING();

    aspace_sample_spec_parsed = true;
    return 0;
}

static int g_aspace_size = 0;
static int g_aspace_capdirty_size = 0;

int
do_aspace_sample(char *lbuf)
{
    static const int FIELDS = sizeof(struct aspace_sample_spec) /
                              sizeof(_spec_field_t);
    uint64_t ts;
    uint64_t aspace_size;
    uint64_t capdirty_size;

    if (!aspace_sample_spec_parsed)
        errx(1, "Missing specification '@record-type:aspace-sample'");

    int i = 0, fields = 0;
    for(char *field, *rest = lbuf; (field = strsep(&rest, "\t\n")) != NULL; i++) {
        if (aspace_sample_spec.ts.i == i) {
            int err = 0;
            char *ts_str = field;
            ts = estrtoull(ts_str, 10, &err);
            if (err)
                errx(1, "Bad timestamp '%s'"
                        "\nat line %d: '%s'", ts_str, line_no, line);
            fields++;
        } else if (aspace_sample_spec.aspace_size.i == i) {
            int err = 0;
            char *aspace_size_str = field;
            aspace_size = estrtoull(aspace_size_str, 10, &err);
            if (err)
                errx(1, "Bad addr-space-size '%s'"
                        "\nat line %d: '%s'", aspace_size_str, line_no, line);
            fields++;
        } else if (aspace_sample_spec.aspace_capdirty_size.i == i) {
            int err = 0;
            char *capdirty_size_str = field;
            capdirty_size = estrtoull(capdirty_size_str, 10, &err);
            if (err)
                errx(1, "Bad sweep-amount '%s'"
                        "\nat line %d: '%s'", capdirty_size_str, line_no, line);
            fields++;
        }
        if (fields == FIELDS) break;
    }
    if (fields < FIELDS) {
        fprintf(stderr, "Bad 'aspace-sample' record line with only %d out of %d "
                "required fields"
                "\n\tat line %d: '%s'\n", fields, FIELDS, line_no, line);
        return 1;
    }

    if (g_aspace_capdirty_size < capdirty_size) {
        size_t d = capdirty_size - g_aspace_capdirty_size;
        g_aspace_capdirty_size += mapd_aspace_add(d);
    } else if (g_aspace_capdirty_size > capdirty_size) {
        size_t d = g_aspace_capdirty_size - capdirty_size;
        g_aspace_capdirty_size -= mapd_aspace_remove(d);
        assert(g_aspace_capdirty_size >= 0);
    }

    return 0;
}

int
main(int argc, char **argv) {
    FILE *f;
    char lbuf[16384];
    int ret;
    bool is_call_trace_spec, is_call_trace;
    bool is_aspace_sample_spec, is_aspace_sample;

    f = stdin;

    assert(sizeof(lbuf) >= sizeof(line));

    while(fgets(line, sizeof(line), f)) {
        line_no++;
        if ((line_no & 0x1ffff) == 0)
            replay_vprintf("Line #%d\n", line_no);
        if (line[0] == '#') {
            continue;
        }
        is_call_trace_spec = strncmp("@record-type:call-trace", line, 23) == 0;
        is_call_trace = !is_call_trace_spec &&
                             strncmp("call-trace", line, 10) == 0;
        is_aspace_sample_spec = !is_call_trace_spec && !is_call_trace &&
                             strncmp("@record-type:aspace-sample", line, 26)==0;
        is_aspace_sample = !is_call_trace_spec && !is_call_trace_spec &&
                             !is_aspace_sample_spec &&
                             strncmp("aspace-sample", line, 13) == 0;
        if (!is_call_trace_spec && !is_call_trace &&
            !is_aspace_sample_spec && !is_aspace_sample) {
            replay_vprintf("SKIP RECORD LINE %d: %s", line_no, line);
            continue;
        }

        // Copying is only done to preserve the otherwise strsep'd line for
        // error reporting.  Copying could be avoided if
        // - the parsing code undoes strsep()'s effect;
        // - not reporting full call-trace lines altogether
        strcpy(lbuf, line);
        if (is_call_trace_spec) {
            ret = do_call_trace_spec(lbuf);
        } else if (is_call_trace) {
            ret = do_call_trace(lbuf);
        } else if (is_aspace_sample_spec) {
            ret = do_aspace_sample_spec(lbuf);
        } else if (is_aspace_sample) {
            ret = do_aspace_sample(lbuf);
        }
        if (ret)
            replay_vprintf("SKIP RECORD LINE %d: %s", line_no, line);
    }

    if (!feof(f) && ferror(f)) {
        err(errno, NULL);
    }
    return 0;
}
