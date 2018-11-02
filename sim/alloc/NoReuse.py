#!/usr/bin/env python3

# Transform a trace into a one obtained from a very simple bump-the-pointer
# allocator.  This gives an example of a trace-to-trace transformation,
# using both Run and Unrun and might be directly useful as input to other
# allocation models which want to treat the trace VA as an OID.

from common.misc import Publisher
from common.intervalmap import IntervalMap
from sim.RenamingAllocatorBase import RenamingAllocatorBase

class Allocator (RenamingAllocatorBase):
  __slots__ = ('_maxeva', '_eva2sz', '_state')

  def __init__(self, **kwargs):
    super().__init__()
    self._eva2sz = {}
    self._maxeva = 0
    self._state = IntervalMap(4096, 2**64, False)

  def _alloc(self, stk, tid, sz):
    # Impose a minimum size on all allocations, so that, in particular,
    # zero-size allocations are still distinct entities, as required by
    # POSIX.
    if sz < 4 : sz = 4

    res = self._maxeva
    self._maxeva += sz

    self._eva2sz[res] = sz
    self._state.mark(res, sz, True)

    return res

  def _free(self, stk, tid, eva):
    self._state.mark(eva, self._eva2sz[eva], False)
    del self._eva2sz[eva]

  def _try_realloc(self, stk, tid, oeva, nsz):
    return False
