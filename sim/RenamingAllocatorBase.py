#!/usr/bin/env python3

# A base class that takes care of renaming allocator objects, discarding
# map, unmap, and revocation events from the input trace.
# 
# Children should implement all their logic transitively in
#
#  _alloc(size) -> eva
#  _free(eva) -> None
#  _try_realloc(eva, nsz) -> Bool
#
# Children should publish their own version of events that this module
# swallows, specifically:
#
#   mapd
#   unmapd
#   revoked
#
# Children should not publish allocd, freed, reallocd, or size_measured
# events, leaving that to this class.  size_measured is passed through
# unmodified.

from common.publisher import Publisher

class RenamingAllocatorBase (Publisher):
  __slots__ = ('_tva2eva')

  def __init__(self):
    super().__init__()
    self._tva2eva = {}

  # Alloc then publish, which is the natural order of effects
  def allocd(self, begin, end):
    # if begin == 0 : return  # Don't translate failing applications

    sz = end - begin
    eva = self._alloc(sz)
    self._tva2eva[begin] = eva
    self._publish('allocd', eva, eva+sz)

  # Publish then free, so that effects occur in the right order!
  def freed(self, begin):
    eva = self._tva2eva.get(begin, None)
    if eva is not None :
      self._publish('freed', eva)
      self._free(eva)
      del self._tva2eva[begin]

  def reallocd(self, begin_old, begin_new, end_new):
    szn = end_new - begin_new
    evao = self._tva2eva.get(begin_old, None)
    if evao is not None :

      if self._try_realloc(evao, szn) : 
        return self._publish('reallocd', evao,evao,evao+szn)

      # otherwise, alloc new thing, free old thing
      evan = self._alloc(szn)
      self._free(evao)

      # Update TVA map; delete old then add new in case of equality
      del self._tva2eva[begin_old]
      self._tva2eva[begin_new] = evan

      self._publish('reallocd', evao, evan, evan+szn)
    else :
      # We don't seem to have that address on file; allocate it
      # (This should include NULL, yeah?)
      self.allocd(begin_new, end_new)

  # Pass through
  def size_measured(self, sz):
    self._publish('size_measured', sz)

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
