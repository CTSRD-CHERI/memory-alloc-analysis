# Trace producer, the inverse of Run

import itertools
import sys

class Unrun:
    def __init__(self, tslam, out=sys.stdout):
        self._tslam = tslam
        self._out = out

    def allocd(self, publ, begin, end):
        # XXX: call stack not plumbed through yet
        # and we lose information about precisely which allocator call it was
        # (i.e. malloc vs. calloc vs. aligned_alloc vs. posix_memalign ....)
        print("%d\t---\tmalloc\t%d\t%x" % (self._tslam(), end - begin, begin), file=self._out)

    def freed(self, publ, begin):
        print("%d\t\tfree\t%x\t" % (self._tslam(), begin), file=self._out)

    def reallocd(self, publ, begin_old, begin_new, end_new):
        # XXX: call stack not plumbed through yet
        print("%d\t---\trealloc\t%x %d\t%x" % (self._tslam(), begin_old, end_new - begin_new, begin_new), file=self._out)

    def mapd(self, publ, begin, end):
        print("%d\t---\tmmap\t0 %d\t%x" % (self._tslam(), end - begin, begin))

    def unmapd(self, publ, begin, end):
        print("%d\t---\tmunmap\t%x %d\t" % (self._tslam(), begin, end - begin))

    def revoked(self, publ, spans):
        print("%d\t\trevoke\t%s\t" % (self._tslam(), " ".join(map(str,itertools.chain.from_iterable([[b,e] for (b,e) in spans])))))

    def size_measured(self, publ, size):
        print("%d\t%d" % (self._tslam(), size))
