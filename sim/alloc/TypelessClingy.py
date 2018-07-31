#!/usr/bin/env python3

# Cling-inspired allocator model.  Buckets allocations below some threshold,
# with a bump-the-pointer allocator for each.

# Preamble and global parameters -------------------------------------- {{{

import argparse
from bisect import insort
from enum import Enum, unique
import logging
import sys

from common.intervalmap import IntervalMap
from common.misc import Publisher
from sim.RenamingAllocatorBase import RenamingAllocatorBase

# Power of two, greater than page log
bucklog = 16
pagelog = 12

# Various symbolic names for paranoia levels
PARANOIA_STATE_ON_REVOKE=0
PARANOIA_STATE_PER_OPER=1

# --------------------------------------------------------------------- }}}
# Bucket lifecycle definition and prose ------------------------------- {{{

@unique
class BuckSt(Enum):
  AHWM = 1
  TIDY = 2
  BUMP = 3
  WAIT = 4
  JUNK = 5
  __repr__ = Enum.__str__

# Bucket lifecycle:
#
#   All buckets initially are considered AHWM, meaning that there are
#   certainly no pointers into this bucket and that it has never been used.
#   ("Above High Water Mark")
#
#   TIDY means that there are certainly no pointers into this bucket, but
#   that it may have been used before.
#
#   When an allocation request arrives, there are three cases to consider:
#
#     If the allocation is "large", then we must find several TIDY or AHWM
#     buckets to back it.  These buckets are immediately transitioned to
#     WAIT state and are MAPPED.
#
#     If there already exists a bucket for this allocation size in BUMP
#     state, bump its allocation pointer to service the new allocation.
#     If this fills the bucket, transition it to WAIT state, otherwise,
#     leave it in BUMP state.
#
#     Otherwise, find a TIDY or AHWM bucket and transition it to BUMP state,
#     setting its size, seeding its initial bitmap, and marking its pages
#     as MAPPED.  AHWM buckets come from beyond our maximum allocated
#     address and TIDY buckets from a reused bucket below that address, based
#     on some permitted "slop" threshold.
#
#   When a free arrives, there are several cases as well:
#
#     If the target is a large object, transition all backing buckets to
#     JUNK state and UNMAP them.
#
#     Otherwise, set the bit in the bucket's bitmap.
#       If the page's bitmap is now full, UNMAP it. (XXX not yet)
#       If the bucket's bitmap is full, transition the bucket to JUNK.
#
#   A free might also cause us to cross our "slop" threshold; if so, we
#   will engage in one round of revocation of the largest contiguous block
#   of JUNK or TIDY space, moving all blocks therein to TIDY.  (The
#   re-revocation of TIDY space may be surprising, but this reduces the
#   pathology of interdigitated JUNK and TIDY causing many small
#   revocations)

# --------------------------------------------------------------------- }}}
# Size-related utility functions -------------------------------------- {{{
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

# --------------------------------------------------------------------- }}}

class Allocator(RenamingAllocatorBase):
# Initialization ------------------------------------------------------ {{{
  __slots__ = (
        '_bix2state',
        '_bix2szbm',
        '_maxbix',
        '_njunkb',
        '_overhead_factor',
        '_paranoia',
        '_revoke_k',
        '_sz2bixp')

  def __init__(self, **kwargs):
    super().__init__()

# Argument parsing ---------------------------------------------------- {{{
    argp = argparse.ArgumentParser()
    argp.add_argument('overhead_factor', action='store',
                      type=float, default=1.5)
    argp.add_argument('--realloc', action='store',
                      type=str, default="always",
                      choices=['always', 'yes', 'onlyshrink', 'never', 'no'])
    argp.add_argument('--paranoia', action='store', type=int, default=0)
    argp.add_argument('--revoke-k', action='store', type=int, default=1)
    args = argp.parse_args(kwargs['cliargs'])

    self._overhead_factor = args.overhead_factor
    self._paranoia        = args.paranoia

    assert args.revoke_k > 0
    self._revoke_k        = args.revoke_k

    if args.realloc == "never" or args.realloc == "no" :
        self._try_realloc = self._try_realloc_never
    elif args.realloc == "onlyshrink" :
        self._try_realloc = self._try_realloc_onlyshrink
    else:
        self._try_realloc = self._try_realloc_yes
# --------------------------------------------------------------------- }}}

    self._tva2eva = {}  # Object map
    self._maxbix = 0    # Next never-touched bucket index
    self._sz2bixp = {}  # BUMP buckets and allocation pointer, by size
    self._bix2szbm = {} # BUMP and WAIT buckets' size and bitmaps
    self._njunkb = 0    # Number of buckets in JUNK state
    self._bix2state = IntervalMap(0, 2**(64 - bucklog), BuckSt.AHWM)
# --------------------------------------------------------------------- }}}
# Additional state assertions and diagnostics ------------------------- {{{

  def _state_diag(self):
    return (self._bix2szbm, self._sz2bixp, [x for x in self._bix2state])

  def _state_asserts(self):
    # logging.debug("%r %r %r", self._bix2szbm, self._sz2bixp, [x for x in self._bix2state])

    # Ensure that our _maxbix looks like the HWM
    (mbase, msz, mv) = self._bix2state[self._maxbix]
    assert mbase + msz == 2**(64 - bucklog), ("maxbix not max", self._maxbix, mbase, msz, mv)
    assert mv == BuckSt.AHWM, ("maxbix not AHWM", self._maxbix, mbase, msz, mv)

    # Check that our running sum of JUNK pages is correct
    js = [sz for (_, sz, v) in self._bix2state if v == BuckSt.JUNK]
    assert self._njunkb == sum(js), "JUNK accounting botch"

    # Ensure that BUMP states are backed in dictionaries
    for b in [(l,sz) for (l,sz,v) in self._bix2state if v == BuckSt.BUMP] :
        for bc in range(b[0],b[0]+b[1]):
            (bsz, _) = self._bix2szbm[bc]
            assert self._sz2bixp.get(bsz) is not None, \
                ("BUMP miss ix", bc, bsz, self._state_diag())
            assert self._sz2bixp[bsz][0] == bc, \
                ("BUMP miss eq", bc, bsz, self._state_diag())

    # Same for WAIT states.  Not all WAIT-state buckets are necessarily indexed,
    # tho', so we have to be somewhat careful
    for b in [(l,sz) for (l,sz,v) in self._bix2state if v == BuckSt.WAIT] :
        bc = b[0]
        bce = b[0] + b[1]
        while bc < bce:
            assert self._bix2szbm.get(bc) is not None, \
                ("B/W miss", bc, self._state_diag())
            (bsz, _) = self._bix2szbm[bc]
            bc += (bsz + 2**bucklog - 1) >> bucklog

    # Every currently-active BUMP bucket is tagged as such, yes?
    for sz in self._sz2bixp :
        (bc, _) = self._sz2bixp[sz]
        (_, _, v) = self._bix2state[bc]
        assert v == BuckSt.BUMP, ("BUMP botch", bc, v, self._state_diag())

    # All busy buckets are marked as such?
    for bc in self._bix2szbm :
        (_, _, v) = self._bix2state[bc]
        assert v in [BuckSt.BUMP, BuckSt.WAIT], ("B/W botch", bc, v, \
                    self._state_diag())

# --------------------------------------------------------------------- }}}
# Revocation logic ---------------------------------------------------- {{{

  # An actual implementation would maintain a prioqueue or something;
  # we can get away with a linear scan.
  def _find_largest_revokable_spans(self, n=1):
    # Exclude AHWM, which is like TIDY but would almost always be biggest
    okst = {BuckSt.TIDY, BuckSt.JUNK}

    bests = [(0, (None, None))] # [(sz, (bix, njunk))] in ascending order
    cursorbix = 0
    while cursorbix < self._maxbix :
        (qbase, qsz, qv) = self._bix2state.get(cursorbix,
                            coalesce_with_values=okst)
        assert qbase == cursorbix, "JUNK hunt index"
        # Advance cursor now so we can just continue in the below tests
        cursorbix += qsz

        # Smaller or busy spans don't interest us
        if qsz <= bests[0][0] : continue
        if qv not in okst : continue

        # Reject spans that are entirely TIDY already.
        js = [sz for (_, sz, v) in self._bix2state[qbase:qbase+qsz]
                  if v == BuckSt.JUNK]
        if js == [] : continue

        insort(bests, (qsz, (qbase, sum(js))))
        bests = bests[(-n):]

    return bests

  def _try_revoke(self) :
    nbusy = len(self._bix2szbm)
    if self._maxbix >= self._overhead_factor * nbusy :

        # Periodically check that we've gotten it right
        if self._paranoia > PARANOIA_STATE_ON_REVOKE : self._state_asserts()

        brss = self._find_largest_revokable_spans(n=self._revoke_k)
        brss = [ (bix, sz, nj) for (sz, (bix, nj)) in brss if sz > 0 ]
        for brs in brss :
            self._njunkb -= brs[2]
            self._bix2state.mark(brs[0],brs[1],BuckSt.TIDY)

        brss = [(bix << bucklog, (bix+sz) << bucklog) for (bix, sz, _) in brss]
        self._publish('revoked', brss)

# --------------------------------------------------------------------- }}}
# Allocation ---------------------------------------------------------- {{{

  # Find a TIDY|AHWM location for reqbsz buckets and transition them into
  # newst
  def _locnew(self, reqbsz, nst):
    # A linear search isn't too terrible, I suppose
    for (base, sz, val) in self._bix2state :
      if val not in { BuckSt.TIDY, BuckSt.AHWM } : continue
      if sz < reqbsz : continue
      if base >= self._maxbix : continue

      self._maxbix = max(self._maxbix, base + reqbsz)

      self._bix2state.mark(base, reqbsz, nst)
      return base

    loc = self._maxbix
    self._maxbix += reqbsz
    self._bix2state.mark(loc, reqbsz, nst)
    return loc

  def _alloc(self, sz):
    logging.debug(">_alloc sz=%d", sz)
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    if _issmall(sz) :
      # Is small allocation

      # Is bump bucket available?
      sz = _szfix(sz)
      bb = self._sz2bixp.get(sz)
      if bb is None :
        # No, conjure one up and MAP it
        bbix = self._locnew(1, BuckSt.BUMP)
        self._publish('mapd', bbix << bucklog, (bbix+1) << bucklog)

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

      res = (bbix << bucklog) + (bbap-1)*sz
    else :
      # Large allocation.  Immediately acquire, MAP, and enroll in WAIT state
      bsz = int((sz + 2**bucklog - 1) >> bucklog)
      bbix = self._locnew(bsz, BuckSt.WAIT)
      self._bix2szbm[bbix] = (sz, 0)
      res = bbix << bucklog
      self._publish('mapd', res, res + (bsz << bucklog))

    logging.debug("<_alloc eva=%x", res)
    return res

# --------------------------------------------------------------------- }}}
# Free ---------------------------------------------------------------- {{{

  def _free(self, eva) :
    logging.debug(">_free eva=%x", eva)
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    # Look up existing allocation
    bix = eva >> bucklog
    b   = self._bix2szbm[bix]

    # Sanity check state
    (spanbase, spansize, spanst) = self._bix2state.get(bix)
    assert (spanst == BuckSt.BUMP) or (spanst == BuckSt.WAIT), \
      "Attempting to free in non-BUMP/WAIT bucket"

    (sz, bbm) = b
    if _issmall(sz) :
      # Small allocation.  Set bit in bitmask.
      boff = eva - (bix << bucklog)
      assert boff % sz == 0, "Nonzero phase in small bucket"
      bitix = int(boff / sz)
      bitm  = 1 << bitix
      assert bbm & bitm == 0, "Free of bitmask-free object"
      bbm |= bitm

      if spanst == BuckSt.BUMP :
        (bbix, bbap) = self._sz2bixp[sz]
        assert bbix == bix, ("Free in a BUMP bucket but not the BUMP bucket", \
            sz, bix, bbix)
        assert bitix < bbap, ("Free in BUMP bucket beyond alloc ptr", \
            sz, bix, bitix, bbap)

      if bbm == (1 << _maxoix(sz)) - 1 :
        # All objects now free; move bucket state
        assert self._sz2bixp.get(sz) is None or self._sz2bixp[sz][0] != bix, \
          ("Freeing bucket still registered as bump block", \
            bix, sz, self._bix2szbm[bix], self._sz2bixp.get(sz))
        assert spanst == BuckSt.WAIT, "Freeing bucket in non-WAIT state"
        del self._bix2szbm[bix]
        self._bix2state.mark(bix, 1, BuckSt.JUNK)
        self._njunkb += 1

        # XXX At the moment, we only unmap when the entire bucket is free.
        # This is just nwf being lazy and not wanting to do the bit math for
        # page-at-a-time release.
        self._publish('unmapd', bix << bucklog, (bix+1) << bucklog)

        self._try_revoke()
      else :
        # Just update
        self._bix2szbm[bix] = (sz, bbm)
    else :
      # Large allocation, retire all blocks to JUNK, UNMAP, and maybe revoke
      bsz = int((sz + 2**bucklog - 1) >> bucklog)
      del self._bix2szbm[bix]

      assert spanst == BuckSt.WAIT, \
        ("Freeing large span in incorrect state", sz, spanst, bix, b, self._state_diag())
      assert bix + bsz <= spanbase + spansize, \
        "Mismatched bucket states of large allocation"

      self._njunkb += bsz
      self._bix2state.mark(bix, bsz, BuckSt.JUNK)
      self._publish('unmapd', bix << bucklog, (bix+bsz) << bucklog)
      self._try_revoke()
    logging.debug("<_free eva=%x", eva)

# --------------------------------------------------------------------- }}}
# Reallocation -------------------------------------------------------- {{{

  # Since we sometimes allocate a bit more than we need, our realloc is
  # potentially nontrivial.  We're being a little sloppy if we do this,
  # tho', as we're reusing memory without revoking it.  We consider this
  # acceptable, tho', because we presume that realloc does not change the
  # type of the object nor its effective lifetime, and so even if the object
  # temporarily shrinks and then expands, it's still the same object.
  #
  # If you're not convinced by the above, you're exactly the kind of person
  # that --realloc=onlyshrink or --realloc=none are for!
  def _try_realloc_yes(self, oeva, nsz):
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    # Find the size of the existing allocation
    bix = oeva >> bucklog
    b   = self._bix2szbm[bix]

    # Sanity check state
    (spanbase, spansize, spanst) = self._bix2state.get(bix)
    assert (spanst == BuckSt.BUMP) or (spanst == BuckSt.WAIT), \
      "Attempting to realloc in non-BUMP/WAIT bucket"

    (osz, _) = b

    if nsz <= osz :
      logging.debug("<_try_realloc shrink eva=%x", oeva)
      # Shrinking is always fine, I suppose
      # Don't update the block size
      return True

    if _issmall(osz) :
      logging.debug("<_try_realloc small eva=%x", oeva)
      # Small allocation not growing by much.
      return _issmall(nsz) and _szfix(nsz) == osz
      # Unfortunately, even if the next small piece is free, we couldn't
      # use it, because we'd then be waiting for a free() that never came

    # Large allocation getting larger.  If not much larger...
    if nsz <= ((osz + 2**bucklog - 1) >> bucklog) << bucklog :
      logging.debug("<_try_realloc sm enlarging eva=%x (bix=%d) osz=%d nsz=%d %s", \
          bix << bucklog, bix, osz, nsz, self._state_diag())
      self._bix2szbm[bix] = (nsz, 0)
      return True

    # It might happen that we have enough free spans ahead of us that we can
    # just gobble them.
    (nextbase, nextsize, nextst) = self._bix2state.get(bix+(osz >> bucklog))
    if nextst not in { BuckSt.TIDY, BuckSt.AHWM } :
      logging.debug("<_try_realloc up against %s at eva=%x", nextst, oeva)
      return False

    if nsz <= osz + (nextsize << bucklog) :
      logging.debug("<_try_realloc enlarging eva=%x osz=%d nsz=%d", \
          bix << bucklog, osz, nsz)
      self._bix2szbm[bix] = (nsz, 0)
      self._bix2state.mark(bix+(osz >> bucklog),
                           (nsz - osz + 2**bucklog - 1) >> bucklog,
                           BuckSt.WAIT)
      self._publish('mapd', (bix+(osz >> bucklog)) << bucklog, \
                  (bix + ((nsz + 2 **bucklog -1) >> bucklog)) << bucklog)
      return True

    return False

  def _try_realloc_onlyshrink(self, oeva, nsz):
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    # Find the size of the existing allocation
    bix = oeva >> bucklog
    b   = self._bix2szbm[bix]
    # Sanity check state
    (spanbase, spansize, spanst) = self._bix2state.get(bix)
    assert (spanst == BuckSt.BUMP) or (spanst == BuckSt.WAIT), \
      "Attempting to realloc in non-BUMP/WAIT bucket"
    (osz, _) = b
    return nsz <= osz

  def _try_realloc_never(self, oeva, nsz):
    # Don't bother with PARANOIA_STATE_PER_OPER since we're just going to
    # call down anyway

    return False

# --------------------------------------------------------------------- }}}

# vim: set foldmethod=marker:foldmarker={{{,}}}
