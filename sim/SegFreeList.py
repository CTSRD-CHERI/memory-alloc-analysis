# A segregated free list is a collection of dllist objects of spans, indexed
# by some kind of size heuristic.  Each dllist is maintained in LRU order.
# Here, we also maintain
#
#   a global LRU queue
#
#   an index of all free spans, across all size bins, by address,
#     for easy coalesing and sanity checking.
#
# The constructing caller may provide us a method for fetching coalescing
# spans, if they are already maintaining the requisite state; otherwise,
# we will additionally maintain
#
#   an index of the end of all free spans, for internal management of
#   coalescing

from itertools import islice
from pyllist import dllist
from sortedcontainers import SortedDict

class SegFreeListBase :

  __slots__ = ( 'segs'  # bin ix->LRU dllist (va,sz)
              , 'glru'  # LRU dllist va
              , 'adns'  # va->(dllnode in segs, dllnode in glru)
              , 'minv'  # Minimum VA keyed ( == min(self.adns.keys()) )
              , 'acod'  # Ancillary data for coalescing; this is somewhat
                        # gross, but I think it's justified for performance?
              )

  def __init__(self, extcoal=None) :
    self.adns = {}
    self.glru = dllist()
    self.minv = None
    if extcoal is None :
      self.acod = {}
      self.remove = self._remove_intcoal
      self.insert = self._insert_intcoal
      self.crossreference_asserts = self._crossreference_asserts_intcoal
    else :
      self.acod = extcoal
      self.remove = self._remove_common
      self.insert = self._insert_extcoal
      self.crossreference_asserts = self._crossreference_asserts_extcoal

  # Return all segments whose size is either exactly minsz or is greater
  # than minsz by ovh.  Traverses each applicable segment in LRU order.
  def iterfor(self, minsz, ovh) :
    isegix = self._segix(minsz)
    movh = minsz + ovh

    for (va, sz) in self.segs[isegix] :
      if sz == minsz or sz >= movh :
        yield (va, sz)

    # We have a slightly simpler test in the additional segregated lists,
    # as we know there will not be any objects of exactly minsz size.
    for seg in islice(self.segs, isegix+1, None):
      for (va, sz) in seg :
        if sz >= movh :
          yield (va, sz)

  # Remove the span at the given virtual address and return its size
  def _remove_core(self, va) :
    (sdn, gdn) = self.adns.pop(va)
    sdn.list.remove(sdn)
    self.glru.remove(gdn)
    return sdn.value[1]

  def _remove_common(self, va) :
    if va == self.minv :
      self.minv = None if {} == self.adns else min(self.adns.keys())
    return self._remove_core(va)

  def _remove_intcoal(self, va) :
    sz = self._remove_common(va)
    del self.acod[va+sz]
    return sz

  def peek(self, va) :
    (sdn, _) = self.adns[va]
    (_, sz) = sdn.value
    return sz

  # Insert a span containing the virtual addresses [va, va+sz).
  def _insert_core(self, va, sz, front):
    gdn = self.glru.insert(va)                              # global lru
    if front :
      sdn = self.segs[self._segix(sz)].appendleft((va,sz))  # seg lru
    else :
      sdn = self.segs[self._segix(sz)].insert((va,sz))      # seg lru
    self.adns[va] = (sdn, gdn)                              # index
    self.minv = va if self.minv is None else min(self.minv, va)

  def _insert_extcoal(self, va, sz, front=False) :
    (cva, csz) = self.acod(va)
    if va != cva : self._remove_common(cva)              # coalesced left
    if cva + csz != va + sz : self._remove_common(va+sz) # coalesced right
    self._insert_core(cva, csz, front)

  def _insert_intcoal(self, va, sz, front=False) :
    end = va + sz
    lsva = self.acod.get(va)                             # coalesced left
    if lsva is not None :
      va = lsva
      self._remove_common(lsva)
    radn = self.adns.get(end)                            # coalesced right
    if radn is not None :
      end += self._remove_common(end)
    self._insert_core(va, sz, front)
    self.acod[va+sz] = va

  # Retrieve minimum keyed VA
  def minva(self) : return self.minv

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
  def _crossreference_asserts_common(self) :
    # Ensure that all glru entries exist in the index
    for va in self.glru :
      assert self.adns.get(va, None) is not None, \
        ("Un-indexed GLRU span", va)

    # Ensure that all segregated entries exist in the index
    for seg in self.segs :
      for nix in range(0, seg.size) :
        # not quadratic, despite appearances, due to dllist-internal cache
        (va, _) = seg.nodeat(nix).value
        assert self.adns.get(va, None) is not None, \
          ("Un-indexed segmented span", bix, nix, va)

    # Ensure that all indexed entries are on both LRUs.
    for va in self.adns :
      (sdn, gdn) = self.adns[va]
      assert va == gdn.value, ("GLRU va mismatch", va, gdn.value)
      (sva, ssz) = sdn.value
      assert va == sva, ("Seg va mismatch", va, sva)
      assert sdn.list == self.segs[self._segix(ssz)], \
        ("Seg size vs segregation mismatch", ssz)

  def _crossreference_asserts_intcoal(self) :
    for endva in self.acod :
      startva = self.acod[endva]
      (sdn, _) = self.adns[startva]
      (_, sz) = sdn.value
      assert endva == startva + sz, ("End mismatch")
    return self._crossreference_asserts_common()

  def _crossreference_asserts_extcoal(self) :
    for startva in self.adns :
      (cva, csz) = self.acod(startva)
      assert startva == cva, ("Coalesce base botch")
      (sdn, _) = self.adns[startva]
      (_, sz) = sdn.value
      assert sz == csz, ("Coalesce size botch")
    return self._crossreference_asserts_common()

# A simple instatiation
class SegFreeList(SegFreeListBase) :

  def __init__(self, *args, **kwargs) :
    super(__class__,self).__init__(*args, **kwargs)
    self.segs = []
    for i in range(0,7) : self.segs += [dllist()]

  # segregation heuristic
  def _segix(self, sz) :
    assert sz >= 0

    if   sz <   32 : return 0
    elif sz <   64 : return 1
    elif sz <  128 : return 2
    elif sz <  256 : return 3
    elif sz <  512 : return 4
    elif sz < 1024 : return 5
    else           : return 6
