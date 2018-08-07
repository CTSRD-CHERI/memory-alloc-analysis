#!/usr/bin/env python3

# Cling-inspired allocator model.  Buckets allocations below some threshold,
# with a bump-the-pointer allocator for each.

# Preamble and global parameters -------------------------------------- {{{

from abc import ABCMeta, abstractmethod
import argparse
from bisect import insort
from enum import Enum, unique
import logging
import sys

from common.intervalmap import IntervalMap
from common.misc import Publisher
from sim.RenamingAllocatorBase import RenamingAllocatorBase

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
#   TIDY means that there are certainly no pointers into this bucket, even
#   if it may have been used before.
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

class ClingyAllocatorBase(RenamingAllocatorBase):
# Initialization ------------------------------------------------------ {{{
  __slots__ = (
        '_bix2state',
        '_bix2szbm',
        '_bucklog',
        '_lastrevt',
        '_maxbix',
        '_njunkb',
        '_nbwb',
        '_overhead_factor',
        '_pagelog',
        '_paranoia',
        '_revoke_k',
        '_revoke_t',
        '_szbix2ap',
        '_tidy_factor',
        '_tslam')

  __metaclass__ = ABCMeta

  def __init__(self, **kwargs):
    super().__init__()

    self._tslam = kwargs['tslam']

# Argument parsing ---------------------------------------------------- {{{
    argp = argparse.ArgumentParser()
    argp.add_argument('--overhead-factor', action='store',
                      type=float, default=5)
    argp.add_argument('--tidy-factor', action='store',
                      type=int, default=1,
                      help='Suppress revocation if sufficient TIDY')
    argp.add_argument('--realloc', action='store',
                      type=str, default="always",
                      choices=['always', 'yes', 'onlyshrink', 'never', 'no'])
    argp.add_argument('--paranoia', action='store', type=int, default=0)
    argp.add_argument('--revoke-k', action='store', type=int, default=1)
    argp.add_argument('--revoke-min-time', action='store', type=float, default=0)
    args = argp.parse_args(kwargs['cliargs'])

    self._paranoia        = args.paranoia
    if self._paranoia == 0 and __debug__ :
        logging.warn("Assertions still enabled, even with paranoia 0; "
                     "try python -O")
    if self._paranoia != 0 and not __debug__ :
        raise ValueError("Paranoia without assertions will just be slow")

    self._overhead_factor = args.overhead_factor
    self._tidy_factor     = args.tidy_factor

    assert args.revoke_k > 0
    self._revoke_k        = args.revoke_k

    assert args.revoke_min_time >= 0
    self._revoke_t        = args.revoke_min_time * 1E9

    if args.realloc == "never" or args.realloc == "no" :
        self._try_realloc = self._try_realloc_never
    elif args.realloc == "onlyshrink" :
        self._try_realloc = self._try_realloc_onlyshrink
    else:
        self._try_realloc = self._try_realloc_yes
# --------------------------------------------------------------------- }}}

    # Power of two, greater than page log
    self._bucklog = 16
    self._pagelog = 12

    self._lastrevt = 0  # Time of last revocation pass

    self._maxbix = 0    # Next never-touched bucket index (AHWM)
    self._szbix2ap = {} # BUMP allocation pointer by size and bix
    self._bix2szbm = {} # BUMP and WAIT buckets' size and bitmaps
    self._njunkb = 0    # Number of buckets in JUNK state
    self._nbwb = 0      # Number of buckets in BUMP|WAIT states
    self._bix2state = IntervalMap(0, 2**(64 - self._bucklog), BuckSt.AHWM)

# --------------------------------------------------------------------- }}}
# Size-related utility functions -------------------------------------- {{{

  def _issmall(self, sz): return sz <= 2**(self._bucklog-1)

  # Find the right size bucket for a small request.  Starting from 16, we
  # divide the gap between successive powers of two into four regions and map
  # objects into the smallest one larger than their size.  The size sequence,
  # specifically, begins 16 20 24 28 32 40 48 56 64 80 96 112 128 .  We
  # consider only objects smaller than half a bucket (i.e. 2**bucklog bytes)
  # to be "small"; this is captured by _issmall(), above.
  def _szfix(self, sz):
    assert self._issmall(sz)

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

    if d <= (fl >> 1):
      if d <= (fl >> 2) :     return fl + (fl >> 2)
      else :                  return fl + (fl >> 1)
    elif d <= 3 * (fl >> 2) : return fl + 3 * (fl >> 2)
    return cl

  def _maxoix(self, sz):
    return int((2 ** self._bucklog) / self._szfix(sz))

  def _bix2va(self, bix) : return bix << self._bucklog
  def _va2bix(self, va)  : return va  >> self._bucklog

  def _sz2nbucks(self, sz):
    return int((sz + 2**self._bucklog - 1) >> self._bucklog)
  def _nbucks2sz(self, bs) : return bs << self._bucklog

# --------------------------------------------------------------------- }}}
# Additional state assertions and diagnostics ------------------------- {{{

  def _state_diag(self):
    return (self._bix2szbm, self._szbix2ap, [x for x in self._bix2state])

  def _state_asserts(self):
    # if __debug__ : logging.debug("%r %r %r", self._bix2szbm, self._szbix2ap, [x for x in self._bix2state])

    # Ensure that our _maxbix looks like the HWM
    (mbase, msz, mv) = self._bix2state[self._maxbix]
    assert mbase + msz == 2**(64 - self._bucklog), ("maxbix not max", self._maxbix, mbase, msz, mv)
    assert mv == BuckSt.AHWM, ("maxbix not AHWM", self._maxbix, mbase, msz, mv)

    # Check that our running sum of JUNK pages is correct
    njunk = sum([sz for (_, sz, v) in self._bix2state if v == BuckSt.JUNK])
    assert self._njunkb == njunk, "JUNK accounting botch"

    nbw = sum([self._sz2nbucks(self._bix2szbm[b][0]) for b in self._bix2szbm])
    assert self._nbwb == nbw, \
            ("BUMP|WAIT accounting botch", nbw, self._nbwb,
              self._bix2szbm.keys(), [x for x in self._bix2state])

    # Everything adds up, right?
    ntidy = sum([sz for (_,sz,v) in self._bix2state if v == BuckSt.TIDY])
    #      non-AHWM         JUNK         BUMP|WAIT      TIDY
    assert self._maxbix == self._njunkb + self._nbwb  + ntidy, \
           ("General accounting botch", self._maxbix, self._njunkb,
             self._bix2szbm.keys(), [x for x in self._bix2state])

    # Ensure that BUMP states are backed in dictionaries
    for b in [(l,sz) for (l,sz,v) in self._bix2state if v == BuckSt.BUMP] :
        for bc in range(b[0],b[0]+b[1]):
            (bsz, _) = self._bix2szbm[bc]
            assert self._szbix2ap.get(bsz) is not None, \
                ("BUMP miss sz", bc, bsz, self._state_diag())
            assert self._szbix2ap[bsz][bc] is not None, \
                ("BUMP miss ix", bc, bsz, self._state_diag())

    # Same for WAIT states.  Not all WAIT-state buckets are necessarily indexed,
    # tho', so we have to be somewhat careful
    for b in [(l,sz) for (l,sz,v) in self._bix2state if v == BuckSt.WAIT] :
        bc = b[0]
        bce = b[0] + b[1]
        while bc < bce:
            assert self._bix2szbm.get(bc) is not None, \
                ("B/W miss", bc, self._state_diag())
            (bsz, _) = self._bix2szbm[bc]
            bc += self._sz2nbucks(bsz)

    # Every currently-active BUMP bucket is tagged as such, yes?
    for sz in self._szbix2ap :
      for bc in self._szbix2ap[sz]:
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

    bests = [(0, (None, None))] # [(njunk, (bix, sz))] in ascending order
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

        nj = sum(js)
        if nj <= bests[0][0] : continue

        # Sort spans by number of JUNK buckets, not JUNK|TIDY buckets
        insort(bests, (nj, (qbase, qsz)))
        bests = bests[(-n):]

    return bests

  def _do_revoke(self) :
   if self._paranoia > PARANOIA_STATE_ON_REVOKE : self._state_asserts()

   # Find k largest revokable spans
   brss = self._find_largest_revokable_spans(n=self._revoke_k)
   brss = [ (bix, sz, nj) for (nj, (bix, sz)) in brss if sz > 0 ]
   for (bix, sz, nj) in brss :
       self._njunkb -= nj
       self._bix2state.mark(bix,sz,BuckSt.TIDY)

   brss = [(self._bix2va(bix), self._bix2va(bix+sz))
           for (bix, sz, _) in brss]
   self._publish('revoked', "---", brss)

   self._lastrevt = self._tslam()

  def _try_revoke(self) :

    # Revoke only if all of

    # we're above our permitted overhead factor (which is the ratio of BUMP|WAIT to JUNK buckets)
    #
    # we're above our inverse occupancy factor (which is the ratio of BUMP|WAIT to TIDY buckets)
    #
    # It's been more than N seconds since we last revoked

    ts = self._tslam()

    ntidy = self._maxbix - self._njunkb - self._nbwb
    if (     (self._njunkb >= self._overhead_factor * self._nbwb)
         and (self._nbwb >= self._tidy_factor * ntidy)
         and (ts - self._lastrevt >= self._revoke_t)
       ):

        self._do_revoke()

# --------------------------------------------------------------------- }}}
# Allocation ---------------------------------------------------------- {{{

  @abstractmethod
  def _alloc_place_small(self, stk, bbks, tidys) :
    raise NotImplemented()

  def _alloc_place_small_full(self, bbix) :
    pass

  @abstractmethod
  def _alloc_place_large(self, stk, bbks, tidys) :
    raise NotImplemented()

  def _mark_allocated(self, reqbase, reqbsz, nst):
    if self._paranoia > PARANOIA_STATE_PER_OPER:
      assert nst in {BuckSt.BUMP, BuckSt.WAIT}

      okst = {BuckSt.TIDY, BuckSt.AHWM}
      (qbase, qsz, qv) = self._bix2state.get(reqbase,
                            coalesce_with_values=okst)
      assert qv in okst, ("New allocated mark in bad state", qv)
      assert qbase + qsz >= reqbase + reqbsz, "New allocated undersized?"

    if reqbase > self._maxbix :
        # Allocation request leaving a gap; mark the skipped spans as TIDY
        self._bix2state.mark(self._maxbix, reqbase - self._maxbix,
                             BuckSt.TIDY)

    self._nbwb += reqbsz
    self._maxbix = max(self._maxbix, reqbase + reqbsz)
    self._bix2state.mark(reqbase, reqbsz, nst)

  def _alloc(self, stk, sz):
    if __debug__ : logging.debug(">_alloc sz=%d", sz)
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    # XXX should coalesce
    tidys = ((loc, tsz) for (loc, tsz, v) in self._bix2state \
                if v in { BuckSt.TIDY , BuckSt.AHWM })

    if self._issmall(sz) :
      # Is small allocation

      # Is bump bucket available?
      sz = self._szfix(sz)
      bbs = self._szbix2ap.get(sz, {})

      bbix = self._alloc_place_small(stk, iter(bbs.keys()), tidys)
      if bbix not in bbs :
        self._publish('mapd', stk, self._bix2va(bbix), self._bix2va(bbix+1))
        self._mark_allocated(bbix, 1, BuckSt.BUMP)
        self._bix2szbm[bbix] = (sz, 0)
        if sz not in self._szbix2ap : self._szbix2ap[sz] = {}
        bbap = 0
      else :
        bbap = bbs[bbix]

      if __debug__:
        # Some sanity-checking doesn't hurt, either.
        (bbsz, bbbm) = self._bix2szbm[bbix]
        assert bbsz == sz, "Incorrect indexing of BUMP buckets"
        assert bbbm & (1 << bbap) == 0, "Attempting to BUMP into free object"

      bbap += 1
      if bbap == self._maxoix(sz) :
        # out of room; can't bump this any more
        del self._szbix2ap[sz][bbix]
        self._bix2state.mark(bbix, 1, BuckSt.WAIT)

        # Inform the placement policy that this one is no-go and won't be
        # coming back, so it can stop tracking metadata about it.
        self._alloc_place_small_full(bbix)
      else :
        assert bbap < self._maxoix(sz), "Allocation pointer beyond maximum"
        # just revise allocation pointer
        self._szbix2ap[sz][bbix] = bbap

      res = self._bix2va(bbix) + (bbap-1)*sz
    else :
      # Large allocation.

      # Placement
      bsz = self._sz2nbucks(sz)
      bbix = self._alloc_place_large(stk, bsz, tidys)

      if __debug__ :
        (pbase, psz, pv) = self._bix2state.get(bbix)
        assert pbase + psz >= bbix + bsz, "Large placement botch"

      # Enroll in WAIT state and map pages
      self._mark_allocated(bbix, bsz, BuckSt.WAIT)
      self._bix2szbm[bbix] = (sz, 0)
      res = self._bix2va(bbix)
      self._publish('mapd', "---", res, res + self._nbucks2sz(bsz))

    self._try_revoke()
    if __debug__ : logging.debug("<_alloc eva=%x", res)
    return res

# --------------------------------------------------------------------- }}}
# Free ---------------------------------------------------------------- {{{

  def _free(self, eva) :
    if __debug__ : logging.debug(">_free eva=%x", eva)
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    # Look up existing allocation
    bix = self._va2bix(eva)
    b   = self._bix2szbm[bix]

    # Sanity check state
    (spanbase, spansize, spanst) = (None, None, None)
    if __debug__:
      (spanbase, spansize, spanst) = self._bix2state.get(bix)
      assert (spanst == BuckSt.BUMP) or (spanst == BuckSt.WAIT), \
        "Attempting to free in non-BUMP/WAIT bucket"

    (sz, bbm) = b
    if self._issmall(sz) :
      # Small allocation.  Set bit in bitmask.
      boff = eva - self._bix2va(bix)
      assert boff % sz == 0, "Nonzero phase in small bucket"
      bitix = int(boff / sz)
      bitm  = 1 << bitix
      assert bbm & bitm == 0, "Free of bitmask-free object"
      bbm |= bitm

      if spanst == BuckSt.BUMP :
        bbs = self._szbix2ap[sz]

        assert bix in bbs, ("Free in BUMP state but not any BUMP bucket", \
            sz, bix, bbix)

        bbap = bbs[bix]

        assert bitix < bbap, ("Free in BUMP bucket beyond alloc ptr", \
            sz, bix, bitix, bbap)

      if bbm == (1 << self._maxoix(sz)) - 1 :
        # All objects now free; move bucket state
        assert bix not in self._szbix2ap.get(sz, {}), \
          ("Freeing bucket still registered as bump block", \
            bix, sz, self._bix2szbm[bix], self._szbix2ap.get(sz))
        assert spanst == BuckSt.WAIT, "Freeing bucket in non-WAIT state"
        del self._bix2szbm[bix]
        self._bix2state.mark(bix, 1, BuckSt.JUNK)
        self._njunkb += 1
        self._nbwb -= 1

        # XXX At the moment, we only unmap when the entire bucket is free.
        # This is just nwf being lazy and not wanting to do the bit math for
        # page-at-a-time release.
        self._publish('unmapd', "---", self._bix2va(bix), self._bix2va(bix+1))

        self._try_revoke()
      else :
        # Just update
        self._bix2szbm[bix] = (sz, bbm)
    else :
      # Large allocation, retire all blocks to JUNK, UNMAP, and maybe revoke
      bsz = self._sz2nbucks(sz)

      assert spanst == BuckSt.WAIT, \
        ("Freeing large span in incorrect state", sz, spanst, bix, b, self._state_diag())
      assert spanbase <= bix and bix + bsz <= spanbase + spansize, \
        "Mismatched bucket states of large allocation"

      del self._bix2szbm[bix]

      self._njunkb += bsz
      self._nbwb -= bsz
      self._bix2state.mark(bix, bsz, BuckSt.JUNK)
      self._publish('unmapd', "---", self._bix2va(bix), self._bix2va(bix+bsz))
      self._try_revoke()
    if __debug__ : logging.debug("<_free eva=%x", eva)

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
    bix = self._va2bix(oeva)
    b   = self._bix2szbm[bix]

    # Sanity check state
    if __debug__ :
      (spanbase, spansize, spanst) = self._bix2state.get(bix)
      assert (spanst == BuckSt.BUMP) or (spanst == BuckSt.WAIT), \
        "Attempting to realloc in non-BUMP/WAIT bucket"

    (osz, _) = b

    if nsz <= osz :
      if __debug__ : logging.debug("<_try_realloc shrink eva=%x", oeva)
      # Shrinking is always fine, I suppose
      # Don't update the block size
      return True

    if self._issmall(osz) :
      if __debug__ : logging.debug("<_try_realloc small eva=%x", oeva)
      # Small allocation not growing by much.
      return self._issmall(nsz) and self._szfix(nsz) == osz
      # Unfortunately, even if the next small piece is free, it's not easy
      # to use it.  While we could grow into it and immediately mark it free
      # (relying on the non-freeness of the current allocation to prevent
      # freeing of the bucket, though this becomes more complicated with
      # page-at-a-time unmapping), subsequent reallocations would not only
      # not be able to do this trick but also fail to copy the additional
      # data, which would be really bad, since the size is derived from the
      # bucket metadata.

    # Large allocation getting larger.  If not much larger...
    if nsz <= self._nbucks2sz(self._sz2nbucks(osz)) :
      if __debug__ : logging.debug("<_try_realloc sm enlarging eva=%x (bix=%d) osz=%d nsz=%d %s", \
          self._bix2va(bix), bix, osz, nsz, self._state_diag())
      self._bix2szbm[bix] = (nsz, 0)
      return True

    # It might happen that we have enough free spans ahead of us that we can
    # just gobble them.
    eix = bix + self._sz2nbucks(osz)

    (nextbase, nextsize, nextst) = self._bix2state.get(eix)
    if nextst not in { BuckSt.TIDY, BuckSt.AHWM } :
      if __debug__ : logging.debug("<_try_realloc up against %s at eva=%x", nextst, oeva)
      return False

    if nsz <= osz + self._nbucks2sz(nextsize) :
      if __debug__ : logging.debug("<_try_realloc enlarging eva=%x osz=%d nsz=%d", \
          self._bix2va(bix), osz, nsz)
      self._bix2szbm[bix] = (nsz, 0)
      self._mark_allocated(eix, self._sz2nbucks(nsz - osz), BuckSt.WAIT)
      self._publish('mapd', "---",
                    self._nbucks2sz(bix + self._sz2nbucks(osz)), \
                    self._nbucks2sz(bix + self._sz2nbucks(nsz)))
      return True

    return False

  def _try_realloc_onlyshrink(self, oeva, nsz):
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    # Find the size of the existing allocation
    bix = self._va2bix(oeva)
    b   = self._bix2szbm[bix]
    # Sanity check state
    if __debug__ :
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
