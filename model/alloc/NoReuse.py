#!/usr/bin/env python3

# Transform a trace into a one obtained from a very simple bump-the-pointer
# allocator.  This gives an example of a trace-to-trace transformation,
# using both Run and Unrun and might be directly useful as input to other
# allocation models which want to treat the trace VA as an OID.

from publisher import Publisher

class Allocator (Publisher):
    def __init__(self, **kwargs):
        super().__init__()
        self._tva2eva = {}
        self._max_eva = 0

    def size_measured(self, sz):
        self._publish('size_measured', sz)

    def _alloc(self, tva, sz):
        # Impose a minimum size on all allocations, so that, in particular,
        # zero-size allocations are still distinct entities, as required by
        # POSIX.
        if sz < 4 : sz = 4

        res = self._max_eva
        self._max_eva += sz

        self._tva2eva[tva] = res

        return res

    def allocd(self, begin, end):
        sz = end - begin
        eva = self._alloc(begin, sz)
        self._publish('allocd', eva, eva+sz)

    def freed(self, begin):
        eva = self._tva2eva.get(begin, None)
        if eva is not None :
            del self._tva2eva[begin]
            self._publish('freed', eva)
        pass

    def reallocd(self, begin_old, begin_new, end_new):
        szn = end_new - begin_new
        evan = self._alloc(begin_new, szn)

        if begin_old == 0 :
            return self._publish('allocd', evan, evan+szn)

        evao = self._tva2eva.get(begin_old, None)
        if evao is not None :
            del self._tva2eva[begin_old]
            self._publish('reallocd', evao, evan, evan+szn)
        else :
            self._publish('allocd', evan, evan+szn)

    # These are hard to pass through, so don't.  In particular, the trace
    # VAs are not linear in the emulated VA space, so a single map block
    # would translate to many spans in the emulated space.  Since, to first
    # order, we are only out to model allocator placements, and can
    # synthesize our own map and unmap events, don't pass these further
    # along the pipeline.
    def mapd(self, begin, end):
        pass

    def unmapd(self, begin, end):
        pass

    def revoked(self, spans):
        pass
