# A segregated free list is a collection of dllist objects of spans, indexed
# by some kind of size heuristic.  Each dllist is maintained in LRU order.
# Here, we also maintain
#
#   a global LRU queue
#
#   an index of all free spans, across all size bins, by address,
#     for easy coalesing and sanity checking.

from pyllist import dllist
from sortedcontainers import SortedDict

class SegFreeList :

  __slots__ = ( 'segs'  # bin ix->LRU dllist (va,sz)
              , 'glru'  # LRU dllist va
              , 'adns'  # va->(dllnode in segs, dllnode in glru)
              , 'numb'  # Number of bins
              )

  def __init__(self) :
    self.adns = SortedDict()
    self.glru = dllist()
    self.segs = {}
    self.numb = 9
    for i in range(0,self.numb) : self.segs[i] = dllist()

  # segregation heuristic
  def seg(self, sz) :
    assert sz >= 0

    if   sz <   32 : return 0
    elif sz <   64 : return 1
    elif sz <  128 : return 2
    elif sz <  256 : return 3
    elif sz <  512 : return 4
    elif sz < 1024 : return 5
    else           : return self.numb-1

  # Return all segments whose size is either exactly minsz or is greater
  # than minsz by ovh.  Traverses each applicable segment in LRU order.
  def iterfor(self, minsz, ovh) :
    ibix = self.seg(minsz)
    movh = minsz + ovh

    for (va, sz) in self.segs[ibix] :
      if sz == minsz or sz >= movh :
        yield (va, sz)

    # We have a slightly simpler test in the additional segregated lists,
    # as we know there will not be any objects of exactly minsz size.
    for bix in range(ibix+1,self.numb) :
      for (va, sz) in self.segs[bix] :
        if sz >= movh :
          yield (va, sz)

  # Remove the span at the given virtual address and return its size
  def remove(self, va) :
    (sdn, gdn) = self.adns.pop(va)
    sdn.list.remove(sdn)
    self.glru.remove(gdn)
    return sz

  def peek(self, va) :
    (sdn, _) = self.adns[va]
    (_, sz) = sdn.value
    return sz

  # Insert a span containing the virtual addresses [va, va+sz).
  #
  # The caller MUST ensure that this span would not coalesce with any
  # existing span.  This should be used with utmost care; use
  # insert_coalesced if not sure.
  def insert(self, va, sz):
    gdn = self.glru.insert(va)                              # global lru
    sdn = self.segs[self.seg(sz)].insert((va,sz))           # seg lru
    self.adns[va] = (sdn, gdn)                              # index

  # Insert a span containing the virtual addresses [va, va+sz), bridging up
  # to two end-touching segments within [cva, cva+csz). This is somewhat
  # messy; it depends strongly on the caller doing state management that in
  # some sense is ours, but they may be maintaining anyway and so would be
  # silly for us to duplicate.  Before attempting to understand what's going
  # on here, it's probably best to ensure that you understand the simpler,
  # but related, function dll_im_coalesced_insert in common.misc.
  def insert_coalesced(self, va, sz, cva, csz) :
    if va != cva :           # coalesced left
      (lsdn, lgdn) = self.adns.pop(cva)                     # index
      lsdn.list.remove(lsdn)                                # seg lru
      self.glru.remove(lgdn)                                # global lru
    if cva + csz != va + sz : # coalesced right
      (rsdn, rgdn) = self.adns.pop(va + sz)                 # index
      rsdn.list.remove(rsdn)                                # seg lru
      self.glru.remove(rgdn)                                # global lru
    self.insert(cva, csz)

  # Global LRU first element (va, sz); use for debugging and rendering
  def eldest(self) :
    if self.glru.first is not None :
      va = self.glru.first.value
      (sdn, _) = self.adns[va]
      return sdn.value
    return None

  # Global LRU iterator (va, sz); used only for debugging
  def iterlru(self) :
    for va in self.glru :
      (sdn, _) = self.adns[va]
      (sva, _) = sdn.value
      assert va == sva
      yield sdn.value

  # Ensure that internal invariants hold
  def crossreference_asserts(self) :
    # Ensure that all glru entries exist in the index
    for va in self.glru :
      assert self.adns.get(va, None) is not None, \
        ("Un-indexed GLRU span", va)

    # Ensure that all segregated entries exist in the index
    for bix in self.segs :
      for nix in range(0, self.segs[bix].size) :
        # not quadratic, despite appearances, due to dllist-internal cache
        (va, _) = self.segs[bix].nodeat(nix).value
        assert self.adns.get(va, None) is not None, \
          ("Un-indexed segmented span", bix, nix, va)

    # Ensure that all indexed entries are on both LRUs.
    for va in self.adns :
      (sdn, gdn) = self.adns[va]
      assert va == gdn.value, ("GLRU va mismatch", va, gdn.value)
      (sva, ssz) = sdn.value
      assert va == sva, ("Seg va mismatch", va, sva)
      assert sdn.list == self.segs[self.seg(ssz)], \
        ("Seg size vs segregation mismatch", ssz)

