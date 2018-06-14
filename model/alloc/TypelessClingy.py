#!/usr/bin/env python3

# Cling-inspired allocator model.  Buckets allocations below some threshold,
# with a bump-the-pointer allocator for each.

from enum import Enum, unique
import sys

from intervalmap import IntervalMap
from publisher import Publisher

# Power of two, greater than page log
bucklog = 16
pagelog = 12

@unique
class BuckSt(Enum):
  TIDY = 1
  BUMP = 2
  WAIT = 3
  JUNK = 4
  __repr__ = Enum.__str__

# Bucket lifecycle:
#
#   All buckets initially are considered TIDY, meaning that there are
#   certainly no pointers into this bucket.
#
#   When an allocation request arrives, there are three cases to consider:
#
#     If the allocation is "large", then we must find several TIDY
#     buckets to back it.  These buckets are immediately transitioned to
#     WAIT state and are MAPPED.
#
#     If there already exists a bucket for this allocation size in BUMP
#     state, bump its allocation pointer to service the new allocation.
#     If this fills the bucket, transition it to WAIT state, otherwise,
#     leave it in BUMP state.
#
#     Otherwise, find a TIDY bucket and transition it to BUMP state,
#     setting its size, seeding its initial bitmap, and marking its pages
#     as MAPPED.  TIDY buckets come from beyond our maximum allocated
#     address or from a reused bucket below that address, based on some
#     permitted "slop" threshold.
#
#   When a free arrives, there are several cases as well:
#
#     If the target is a large object, transition all backing buckets to
#     JUNK state and UNMAP them.
#
#     Otherwise, set the bit in the bucket's bitmap.  If the page's bitmap
#     is now full, UNMAP it.  If the bucket's bitmap is full, transition
#     the bucket to JUNK (necessarily from WAIT).
#
#   A free might also cause us to cross our "slop" threshold; if so, we
#   will engage in one round of revocation of the largest contiguous block
#   of JUNK|TIDY space, moving all blocks therein to TIDY.  (The
#   re-revocation of TIDY space may be surprising, but this reduces the
#   pathology of interdigitated JUNK and TIDY causing many small
#   revocations)

# XXX The bits above about MAP and UNMAP are aspirational
# XXX As are the actual revocation bits.  Shouldn't be hard, just not done.

def _szfix(sz):
  assert sz <= 2**(bucklog-1)

  if sz <= 16 : return 16

  # XXX
  # At 1/4 linear separation between successive powers of two, we
  # are only guaranteed 16/4 = 4 byte alignment of objects.  If we
  # really want to get down to it, we could try doing something more
  # clever here or we could enforce that we always allocate objects
  # with size max(requested_size, alignment*4).
  bl = sz.bit_length() - 1
  fl = 1 << bl

  d = sz - fl
  if d == 0 : return sz

  cl = fl << 1
  assert fl <= sz < cl

  if d <= (fl >> 1) :
    if d <= (fl >> 2) :   return fl + (fl >> 2)
    else:         return fl + (fl >> 1)
  elif d <= 3 * (fl >> 2) : return fl + 3 * (fl >> 2)
  return cl

def _issmall(sz) : return sz <= 2**(bucklog-1)
def _maxoix(sz) : return int((2 ** bucklog) / _szfix(sz))

class Allocator(Publisher):
  def __init__(self, **kwargs):
    super().__init__()

    self._tva2eva = {}  # Object map
    self._maxbix = 0  # Next never-touched bucket index
    self._sz2bixp = {}  # BUMP buckets and allocation pointer, by size
    self._bix2szbm = {} # BUMP and WAIT buckets' size and bitmaps
    self._bix2state = IntervalMap(0, 2**(64 - bucklog), BuckSt.TIDY)

  def _locnew(self, reqbsz, nst):
    for (base, sz, val) in self._bix2state :
      if val != BuckSt.TIDY : continue
      if sz < reqbsz : continue
      if base >= self._maxbix : continue

      self._bix2state.mark(base, reqbsz, nst)
      return base

    loc = self._maxbix
    self._maxbix += reqbsz
    self._bix2state.mark(loc, reqbsz, nst)
    return loc
 
  def _alloc(self, sz):
    if _issmall(sz) :
      # Is small allocation

      # Is bump bucket available?
      sz = _szfix(sz)
      bb = self._sz2bixp.get(sz)
      if bb is None :
        # No, conjure one up
        bbix = self._locnew(1, BuckSt.BUMP)

        # Register its size and bitmap
        self._bix2szbm[bbix] = (sz, 0)
        bbap = 0
      else :
        # Yes, so let's use it
        (bbix, bbap) = bb

      # Some sanity-checking doesn't hurt, either.
      (bbsz, bbbm) = self._bix2szbm[bbix]
      assert bbsz == sz, "Incorrect indexing of BUMP buckets"
      assert bbbm & (1 << bbap) == 0, "Attempting to BUMP into free object"

      bbap += 1
      if bbap == _maxoix(sz) :
        # out of room; can't bump this any more
        del self._sz2bixp[sz]
        self._bix2state.mark(bbix, 1, BuckSt.WAIT)
      else :
        assert bbap < _maxoix(sz), "Allocation pointer beyond maximum"
        # just revise allocation pointer
        self._sz2bixp[sz] = (bbix, bbap)

      return (bbix << bucklog) + (bbap-1)*sz
    else :
      bsz = int((sz + 2**bucklog - 1) >> bucklog)
      bbix = self._locnew(bsz, BuckSt.WAIT)
      self._bix2szbm[bbix] = (sz, 0)

      return bbix << bucklog

  def _free(self, eva) :
    # Look up existing allocation
    bix = eva >> bucklog
    b   = self._bix2szbm[bix]

    # Sanity check state
    (spanbase, spansize, spanst) = self._bix2state.get(bix)
    assert (spanst == BuckSt.BUMP) or (spanst == BuckSt.WAIT), \
      "Attempting to free in non-BUMP/WAIT bucket"

    (bsz, bbm) = b
    if _issmall(bsz) :
      # Small allocation.  Set bit in bitmask.
      boff = eva - (bix << bucklog)
      assert boff % bsz == 0, "Nonzero phase in small bucket"
      bitix = int(boff / bsz)
      bitm  = 1 << bitix
      assert bbm & bitm == 0, "Free of bitmask-free object"
      bbm |= bitm
      if bbm == (1 << _maxoix(bsz)) - 1 :
        # All objects now free; move page state
        del self._bix2szbm[bix]
        assert self._sz2bixp.get(bsz) is None or self._sz2bixp[bsz][1] != bix, \
          "Freeing bucket still registered as bump block"
        assert spanst == BuckSt.WAIT, "Freeing bucket in non-WAIT state"
        self._bix2state.mark(bix, 1, BuckSt.JUNK)
      else :
        # Just update
        self._bix2szbm[bix] = (bsz, bbm)
    else :
      # Large allocation, retire all blocks to JUNK
      bsz = int((bsz + 2**bucklog - 1) >> bucklog)
      del self._bix2szbm[bix]

      assert bix + bsz <= spanbase + spansize, \
        "Mismatched bucket states of large allocation"

      self._bix2state.mark(bix, bsz, BuckSt.JUNK)

  def _try_realloc(self, oeva, nsz):
    # Find the size of the existing allocation
    bix = oeva >> bucklog
    b   = self._bix2szbm[bix]

    # Sanity check state
    (spanbase, spansize, spanst) = self._bix2state.get(bix)
    assert (spanst == BuckSt.BUMP) or (spanst == BuckSt.WAIT), \
      "Attempting to realloc in non-BUMP/WAIT bucket"

    (bsz, _) = b

    if nsz <= bsz :
      # Shrinking is always fine, I suppose
      # Don't update the block size
      return True

    if _issmall(nsz) :
      # Small allocation not growing by much.
      return _szfix(nsz) == bsz 
      # Unfortunately, even if the next small piece is free, we couldn't
      # use it, because we'd then be waiting for a free() that never came

    # Large allocation getting larger.  If not much larger...
    if nsz <= ((bsz + 2**bucklog - 1) >> bucklog) << bucklog :
        self._bix2szbm[bix] = (nsz, 0)
        return True

    # It might happen that we have enough free spans ahead of us that we can
    # just gobble them.
    (nextbase, nextsize, nextst) = self._bix2state.get(bix+(bsz >> bucklog))
    if nextst != BuckSt.TIDY : return False

    if nsz <= bsz + (nextsize << bucklog) :
        self._bix2szbm[bix] = (nsz, 0)
        self._bix2state.mark(bix+(bsz >> bucklog),
                             (nsz - bsz + 2**bucklog - 1) >> bucklog,
                             BuckSt.WAIT)
        return True

    return False

  def allocd(self, begin, end):
    sz = end - begin
    eva = self._alloc(sz)
    self._tva2eva[begin] = eva
    self._publish('allocd', eva, eva+sz)


  def freed(self, begin):
    eva = self._tva2eva.get(begin, None)
    if eva is not None :
      del self._tva2eva[begin]
      self._free(eva)
      self._publish('freed', eva)
    pass
 
  def reallocd(self, begin_old, begin_new, end_new):
    szn = end_new - begin_new
    evao = self._tva2eva.get(begin_old, None)
    if evao is not None :
      # We might be able to leave this in place.  Rarely, but sometimes!
      if self._try_realloc(evao, szn) : 
        return self._publish('reallocd', evao,evao,evao+szn)
      # otherwise, alloc new thing, free old thing
      self.allocd(begin_new, end_new)
      self.freed(begin_old)
    else :
      self.allocd(begin_new, end_new)
 
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

  def size_measured(self, sz):
    self._publish('size_measured', sz)

# def diag():
#   print(c._bix2szbm)
#   print(c._sz2bixp)
#   print([x for x in c._bix2state])
# 
# big1 = c._alloc(2**20)
# sm1 = c._alloc(16)
# big2 = c._alloc(2**20)
# diag()
# c._free(big1)
# diag()
