#!/usr/bin/env python3

# Cling-inspired allocator model.  Buckets allocations below some threshold,
# with a bump-the-pointer allocator for each.
#
# See
# https://www.usenix.org/conference/usenixsecurity10/cling-memory-allocator-mitigate-dangling-pointers
# for more information about Cling.

# Preamble and global parameters -------------------------------------- {{{

from abc import ABCMeta, abstractmethod
import argparse
from bisect import insort
from enum import Enum, unique
import logging
from math import ceil
from pyllist import dllist
import sys

from common.intervalmap import IntervalMap
from common.misc import Publisher, dll_im_coalesced_insert
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

st_at  = {BuckSt.TIDY, BuckSt.AHWM}
st_tj  = {BuckSt.TIDY, BuckSt.JUNK}
st_atj = {BuckSt.TIDY, BuckSt.JUNK, BuckSt.AHWM}


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
#     WAIT state and are MAPPED.  See _alloc_place_large().
#
#     If there already exists a bucket for this allocation size in BUMP
#     state, we *may* bump its allocation pointer to service the new
#     allocation.  There may be several open BUMP buckets for any given
#     size.  See _alloc_place_small().  If this fills the bucket, transition
#     it to WAIT state (see _alloc_place_small_full), otherwise, leave it in
#     BUMP state.
#
#     Otherwise, find a TIDY or AHWM bucket and transition it to BUMP state,
#     setting its size, seeding its initial bitmap, and marking its pages
#     as MAPPED.  AHWM buckets come from beyond our maximum allocated
#     address and TIDY buckets from a reused bucket below that address, based
#     on some permitted "slop" threshold.  See, again, _alloc_place_small().
#
#   When a free arrives, there are several cases as well:
#
#     If the target is a large object, transition all backing buckets from
#     WAIT to JUNK state and UNMAP them.
#
#     Otherwise, set the bit in the bucket's bitmap.
#
#       If the page's bitmap is now full, UNMAP it. (XXX not yet)
#
#       If the bucket's bitmap is full, transition the bucket to JUNK
#       (necessarily from WAIT).
#
#   A free might also cause us to cross our "slop" threshold; if so, we
#   will engage in one round of revocation, moving as many JUNK buckets
#   as possible into TIDY.  To avoid the pathology of interdigitated JUNK
#   and TIDY spans of buckets causing many small revocations, we will
#   permit re-revocation of TIDY buckets, but only if the revocation
#   continues to maximize the number of JUNK buckets transitioning.

bst2color = {
    BuckSt.AHWM : 0x000000, # black (unused)
    BuckSt.TIDY : 0xFFFFFF, # white
    BuckSt.BUMP : 0x0000FF, # red
    BuckSt.WAIT : 0x00FF00, # green
    BuckSt.JUNK : 0xFF0000, # blue
}
cBRS = 0x00FFFF # yellow
cOJS = 0xFF00FF # purple

# --------------------------------------------------------------------- }}}

class ClingyAllocatorBase(RenamingAllocatorBase):
# Initialization ------------------------------------------------------ {{{
  __slots__ = (
        '_bix2state',
        '_bix2szbm',
        '_brscache',
        '_bucklog',
        '_junklru',
        '_junkbdn',
        '_maxbix',
        '_njunkb',
        '_nbwb',
        '_pagelog',
        '_paranoia',
        '_revoke_k',
        '_szbix2ap',
        '_tslam')

  __metaclass__ = ABCMeta

# Argument definition and response ------------------------------------ {{{
  @staticmethod
  def _init_add_args(argp) :
    argp.add_argument('--realloc', action='store',
                      type=str, default="always",
                      choices=['always', 'yes', 'onlyshrink', 'never', 'no'])
    argp.add_argument('--paranoia', action='store', type=int, default=0)
    argp.add_argument('--revoke-k', action='store', type=int, default=1)
    argp.add_argument('--render-style', action='store',
                      type=str, default="compact",
                      choices=['compact', 'expand16'])

  def _init_handle_args(self, args) :
    self._paranoia        = args.paranoia
    if self._paranoia == 0 and __debug__ :
        logging.warn("Assertions still enabled, even with paranoia 0; "
                     "try python -O")
    if self._paranoia != 0 and not __debug__ :
        raise ValueError("Paranoia without assertions will just be slow")

    assert args.revoke_k > 0
    self._revoke_k        = args.revoke_k

    if args.realloc == "never" or args.realloc == "no" :
        self._try_realloc = self._try_realloc_never
    elif args.realloc == "onlyshrink" :
        self._try_realloc = self._try_realloc_onlyshrink
    else:
        self._try_realloc = self._try_realloc_yes

    if args.render_style == "expand16":
        self.render = self._render_expanded

# --------------------------------------------------------------------- }}}

  def __init__(self, **kwargs):
    super().__init__()

    self._tslam = kwargs['tslam']

# Argument parsing ---------------------------------------------------- {{{

    argp = argparse.ArgumentParser()
    self._init_add_args(argp)
    self._init_handle_args(argp.parse_args(kwargs['cliargs']))

# --------------------------------------------------------------------- }}}

    # Power of two, greater than page log
    self._bucklog = 16
    self._pagelog = 12

    self._maxbix = 1    # Next never-touched bucket index (AHWM)
    self._szbix2ap = {} # BUMP allocation pointer by size and bix
    self._bix2szbm = {} # BUMP and WAIT buckets' size and bitmaps
    self._njunkb = 0    # Number of buckets in JUNK state
    self._nbwb = 0      # Number of buckets in BUMP|WAIT states
    self._bix2state = IntervalMap(self._maxbix,
                                  2**(64 - self._bucklog) - self._maxbix,
                                  BuckSt.AHWM)
    self._brscache = None   # Biggest revokable span cache

    self._junklru = dllist()    # List of all revokable spans, LRU
    self._junkbdn = {}          # JUNK bix to node in above list

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

    (njunk, ntidy) = (0, 0)
    for (qb, qsz, qv) in self._bix2state :
        if qv == BuckSt.JUNK :
            # Ensure presence on linked list
            assert self._junkbdn.get(qb,None) is not None, "JUNK not on LRU"
            # Account
            njunk += qsz
        elif qv == BuckSt.TIDY :
            # Account
            ntidy += qsz
        elif qv == BuckSt.BUMP :
            # Ensure that BUMP states are backed in dictionaries
            for bc in range(qb,qb+qsz):
                (bsz, _) = self._bix2szbm[bc]
                assert self._szbix2ap.get(bsz) is not None, \
                    ("BUMP miss sz", bc, bsz, self._state_diag())
                assert self._szbix2ap[bsz][bc] is not None, \
                    ("BUMP miss ix", bc, bsz, self._state_diag())
        elif qv == BuckSt.WAIT :
            # Same for WAIT states.  Not all WAIT-state buckets are
            # necessarily indexed, tho', so we have to be somewhat careful
            bc = qb
            bce = qb + qsz
            while bc < bce:
                assert self._bix2szbm.get(bc) is not None, \
                    ("B/W miss", bc, self._state_diag())
                (bsz, _) = self._bix2szbm[bc]
                bc += self._sz2nbucks(bsz)

    # Check that our running sum of JUNK pages is correct
    assert self._njunkb == njunk, "JUNK accounting botch"

    nbw = 0
    for b in self._bix2szbm :
        # All busy buckets are marked as such?
        (_, _, v) = self._bix2state[b]
        assert v in [BuckSt.BUMP, BuckSt.WAIT], ("B/W botch", bc, v, \
                    self._state_diag())

        # Account
        nbw += self._sz2nbucks(self._bix2szbm[b][0])

    assert self._nbwb == nbw, \
            ("BUMP|WAIT accounting botch", nbw, self._nbwb,
              self._bix2szbm.keys(), [x for x in self._bix2state])

    # Everything adds up, right?
    #      non-AHWM         JUNK         BUMP|WAIT      TIDY
    assert self._maxbix == self._njunkb + self._nbwb  + ntidy, \
           ("General accounting botch", self._maxbix, self._njunkb,
             self._bix2szbm.keys(), [x for x in self._bix2state])

    # Every currently-active BUMP bucket is tagged as such, yes?
    for sz in self._szbix2ap :
      for bc in self._szbix2ap[sz]:
        (_, _, v) = self._bix2state[bc]
        assert v == BuckSt.BUMP, ("BUMP botch", bc, v, self._state_diag())

    # Ensure that JUNK list entries are so stated
    for (jb, jsz) in self._junklru :
        (qb, qsz, qv) = self._bix2state[jb]
        assert qv == BuckSt.JUNK, "LRU not JUNK"
        assert qb == jb and qsz == jsz, "LRU JUNK segment botch"

# --------------------------------------------------------------------- }}}
# Revocation logic ---------------------------------------------------- {{{

  # An actual implementation would maintain a prioqueue or something;
  # we can get away with a linear scan.  We interrogate the bucket state
  # interval map for ease of coalescing, even though we also maintain a
  # parallel JUNK LRU queue.
  def _find_largest_revokable_spans(self, n=1):
    if n == 0 : return
    if n == 1 and self._brscache is not None :
        return [self._brscache]

    bests = [(0, -1, -1)] # [(njunk, bix, sz)] in ascending order
    for (qbase, qsz, qv) in self._bix2state.iter_vfilter(None, self._maxbix, st_tj):

        # Smaller or busy spans don't interest us
        if qsz <= bests[0][0] : continue

        # Reject spans that are entirely TIDY already.
        js = [sz for (_, sz, v) in self._bix2state[qbase:qbase+qsz]
                  if v == BuckSt.JUNK]
        if js == [] : continue

        # Sort spans by number of JUNK buckets, not JUNK|TIDY buckets
        nj = sum(js)
        if nj <= bests[0][0] : continue
        insort(bests, (nj, qbase, qsz))

        bests = bests[(-n):]

    return bests

  def _mark_tidy(self, bix, sz, nj) :
    # Because we coalesce with TIDY spans while revoking, there may be
    # several JUNK spans in here.  Go remove all of them from the LRU.
    for (qbix, qsz, qv) in self._bix2state[bix:bix+sz] :
      assert qv in st_atj, "Revoking non-revokable span"
      if qv == BuckSt.JUNK : self._junklru.remove(self._junkbdn.pop(qbix))

    self._njunkb -= nj
    self._bix2state.mark(bix,sz,BuckSt.TIDY)

    self._brscache = None


  def _do_revoke(self, ss) :
   if self._paranoia > PARANOIA_STATE_ON_REVOKE : self._state_asserts()

   nrev = sum([nj for (nj, _, _) in ss if nj > 0])
   ntidy = self._maxbix - self._njunkb - self._nbwb
   print("Revoking: ts=%.2f hwm=%d busy=%d junk=%d tidy=%d rev=%d rev/hwm=%2.2f%% rev/junk=%2.2f%% ss=%r" \
         % (self._tslam() / 1e9, self._maxbix, self._nbwb, self._njunkb, ntidy,
            nrev, nrev/self._maxbix * 100, nrev/self._njunkb * 100, ss),
         file=sys.stderr)

   for (nj, bix, sz) in ss :
      self._mark_tidy(bix, sz, nj)

   self._publish('revoked', "---", "",
      *((self._bix2va(bix), self._bix2va(bix+sz)) for (_, bix, sz) in ss))


  # Conditionally revokes the top n segments if the predicate, which is
  # given the number of junk buckets in the largest span, says to.
  #
  # If given a "revoke" paramter, it must be an iterable of
  # bases of junk spans which will be guaranteed to be revoked, even if they
  # are not the largest spans known.  This may be used to force some degree
  # of reuse of small spans, as suggested by Hongyan.
  def _predicated_revoke_best(self, fn, n=None, revoke=[]):
    revoke = list(revoke)
    assert len(revoke) <= self._revoke_k

    if n is None :
        n = self._revoke_k

    nrev = None
    brss = None

    if self._brscache is not None :
        # If the best revocable span is cached, just exract the answer
        (nrev, _, _) = self._brscache
    else :
        # Otherwise, answer is not cached, so go compute it now.
        # Compute one more so we can update the cache immediately.
        brss = self._find_largest_revokable_spans(n=n + 1)
        self._brscache = brss[-1]
        nrev = self._brscache[0]

    if fn(nrev) :
      # Revoking the top k spans means that the (k+1)th span is
      # certainly the most productive, in terms of the number of JUNK
      # buckets it contains.  Immediately update the cache to avoid
      # needing another sweep later.
      if brss is None :
        brss = self._find_largest_revokable_spans(n=n + 1)

      assert brss[-1][0] == nrev, \
                ("Incorrect accounting in cache?", brss, nrev, self._brscache)

      # For each mandatory span, fish through the best spans to see if one
      # contains it.  If so, let's revoke the container rather than the
      # containee.
      rset = set()
      for mustbix in revoke:
        for (brnj, brix, brsz) in brss :
          if brix <= mustbix < brix + brsz :
            rset.add((brnj, brix, brsz))
            break
        else :
          # No container found; add the mandatory span, counting the number
          # of junk buckets in it.
          (qix, qsz, _) = self._bix2state.get(mustbix, coalesce_with_values=st_tj)
          rset.add( (sum(sz for (_, sz, v) in self._bix2state[qix:qix+qsz] if v == BuckSt.JUNK),
                     qix, qsz) )

      # Now, go through the best spans until we have at most the number of
      # spans we can revoke in one go.  Since we may have picked some of the
      # best spans while considering mandatory spans above, it's not as
      # simple as just concatenating a list, but it's still not terrible.
      while len(rset) < self._revoke_k and brss != [] :
        rset.add(brss[-1])
        brss = brss[:-1]

      self._do_revoke(rset)

      # Find the largest best span not used and update the cache
      while brss != [] :
        if brss[-1] not in rset : break
        brss = brss[:-1]
      if brss != [] : self._brscache = brss[-1]
      else          : self._brscache = (0, -1, -1)

  @abstractmethod
  def _maybe_revoke(self) :
    # By default, don't!
    #
    # A reasonable implementation of this function will look like a series
    # of checks about the state of the allocator (probing at the accounted
    # _njunkb and _nbwb and _maxbix) and then a call to
    # _predicated_revoke_best with an additional predicate, given the
    # number of buckets that can be reclaimed in the largest revokable
    # (JUNK|TIDY coalesced) span.  I apologize for the interface, but
    # it seemed like a good balance between detailed accounting of the best
    # revokable span at all times or always needing to walk the intervalmap.
    #
    pass

# --------------------------------------------------------------------- }}}
# Allocation ---------------------------------------------------------- {{{

  # Return the bucket index to use for a small placement of size `sz` and
  # made by call stack `stk`.  Available options include the existing bump
  # buckets `bbks` or the TIDY/AHWM segments indicated in `tidys`.  These
  # last two parameters are Python iterators, not lists, to speed up the
  # most common cases.  `tidys` is an iterator of (index, length) tuples,
  # each indicating possibly multiple locations.
  @abstractmethod
  def _alloc_place_small(self, stk, sz, bbks, tidys) :
    raise NotImplemented()

  # Some classes may be associating metadata with bump buckets.  This
  # callback fires whenever a bump bucket fills, to indicate that no future
  # allocations will take place from that bucket and so the metadata can be
  # released.
  def _alloc_place_small_full(self, bbix) :
    pass

  # Return the initial bucket index to use for a large allocation of `sz`
  # *buckets* (not bytes).  `tidys` is, as with `_alloc_place_small`, an
  # iterator of (index, length) pairs.
  @abstractmethod
  def _alloc_place_large(self, stk, sz, tidys) :
    raise NotImplemented()

  def _mark_allocated(self, reqbase, reqbsz, nst):
    if self._paranoia > PARANOIA_STATE_PER_OPER:
      assert nst in {BuckSt.BUMP, BuckSt.WAIT}

      (qbase, qsz, qv) = self._bix2state.get(reqbase,
                            coalesce_with_values=st_at)
      assert qv in st_at, ("New allocated mark in bad state", qv)
      assert qbase + qsz >= reqbase + reqbsz, "New allocated undersized?"

    if reqbase > self._maxbix :
        # Allocation request leaving a gap; mark the skipped spans as TIDY
        # rather than leaving them as AHWM.
        #
        # While this might, technically, change the largest revokable span,
        # it will not change the number of JUNK buckets in any span, and so
        # we need not necessarily invalidate brscache.
        self._bix2state.mark(self._maxbix, reqbase - self._maxbix,
                             BuckSt.TIDY)

    # If the allocation takes place within the current best revokable span,
    # invalidate the cache and let the revocation heuristic reconstruct it.
    if self._brscache is not None :
      (_, brsix, brssz) = self._brscache
      if brsix <= reqbase < brsix + brssz :
        self._brscache = None

    self._nbwb += reqbsz
    self._maxbix = max(self._maxbix, reqbase + reqbsz)
    self._bix2state.mark(reqbase, reqbsz, nst)

  def _alloc(self, stk, tid, sz):
    if __debug__ : logging.debug(">_alloc sz=%d", sz)
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    # XXX should coalesce
    tidys = ((loc, tsz) for (loc, tsz, v) in self._bix2state \
                if v in { BuckSt.TIDY , BuckSt.AHWM })

    if self._issmall(sz) :
      # Is small allocation

      # Is bump bucket available?
      nsz = self._szfix(sz)
      bbs = self._szbix2ap.get(nsz, {})

      bbix = self._alloc_place_small(stk, sz, iter(bbs.keys()), tidys)
      if bbix not in bbs :
        self._publish('mapd', stk, tid, self._bix2va(bbix), self._bix2va(bbix+1), 0b11)
        self._mark_allocated(bbix, 1, BuckSt.BUMP)
        self._bix2szbm[bbix] = (nsz, 0)
        if nsz not in self._szbix2ap : self._szbix2ap[nsz] = {}
        bbap = 0
      else :
        bbap = bbs[bbix]

      if __debug__:
        # Some sanity-checking doesn't hurt, either.
        (bbsz, bbbm) = self._bix2szbm[bbix]
        assert bbsz == nsz, "Incorrect indexing of BUMP buckets"
        assert bbbm & (1 << bbap) == 0, "Attempting to BUMP into free object"

      bbap += 1
      if bbap == self._maxoix(nsz) :
        # out of room; can't bump this any more
        del self._szbix2ap[nsz][bbix]
        self._bix2state.mark(bbix, 1, BuckSt.WAIT)

        # Inform the placement policy that this one is no-go and won't be
        # coming back, so it can stop tracking metadata about it.
        self._alloc_place_small_full(bbix)
      else :
        assert bbap < self._maxoix(nsz), "Allocation pointer beyond maximum"
        # just revise allocation pointer
        self._szbix2ap[nsz][bbix] = bbap

      res = self._bix2va(bbix) + (bbap-1)*nsz
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
      self._publish('mapd', stk, tid, res, res + self._nbucks2sz(bsz), 0b11)

      nsz = self._nbucks2sz(bsz)

    self._maybe_revoke()
    if __debug__ : logging.debug("<_alloc eva=%x", res)
    return (res, nsz)

# --------------------------------------------------------------------- }}}
# Free ---------------------------------------------------------------- {{{

  # Allow for parametrizable behavior when a bucket becomes free.  Should
  # return one of
  #   None  : leave the bucket considered allocated
  #   True  : mark the bucket as JUNK
  #   False : mark the bucket as TIDY immediately
  def _on_bucket_free(self, bix, bsz):
    return True

  # Mark a (span of) bucket(s) JUNK.
  #
  # This may change the largest revocable span, so carry out a single probe
  # of the state intervalmap to see.  Do not attempt to revise the cache
  # here, as that would require counting up the number of JUNK pages in the
  # span returned; just invalidate it and let the revocation heuristic
  # recompute it when needed.
  #
  # Junk spans are also tracked in a LRU cache; do the appropriate juggling
  # here.
  #
  # It may make sense to hook this method in subclasses, too, for further
  # metadata management, especially if we end up designing a "related
  # object" API extension: one may need to refer to metadata of objects
  # whose buckets have already gone from BUMP to BUSY, i.e., for which
  # _alloc_place_small_full() has already been called.
  def _mark_junk(self, bix, bsz) :
    assert self._bix2state[bix][2] != BuckSt.JUNK, "re-marking JUNK"

    del self._bix2szbm[bix]
    self._bix2state.mark(bix, bsz, BuckSt.JUNK)
    self._njunkb += bsz
    self._nbwb -= bsz

    if self._brscache is not None :
      (brsnj, _, _) = self._brscache
      (_, qsz, _) = self._bix2state.get(bix, coalesce_with_values= st_tj)
      if qsz >= brsnj :
        self._brscache = None

    dll_im_coalesced_insert(bix,bsz,self._bix2state,self._junklru,self._junkbdn)

  def _free_bix(self, bix, bsz) :
    r = self._on_bucket_free(bix, bsz)
    if r == True    : self._mark_junk(bix, bsz)
    elif r == False : self._mark_tidy(bix, bsz, 0)
    elif r is None  : pass
    else : assert False, "Invalid return from _on_free_bix: %r" % r

  def _free(self, stk, tid, eva) :
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
        ("Attempting to free in non-BUMP/WAIT bucket:", bix, spanst)

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
        self._free_bix(bix, 1)

        # XXX At the moment, we only unmap when the entire bucket is free.
        # This is just nwf being lazy and not wanting to do the bit math for
        # page-at-a-time release.
        self._publish('unmapd', stk, tid, self._bix2va(bix), self._bix2va(bix+1))

        self._maybe_revoke()
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


      self._free_bix(bix, bsz)
      self._publish('unmapd', stk, tid, self._bix2va(bix), self._bix2va(bix+bsz))
      self._maybe_revoke()
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
  #
  # NB: When making an object smaller, this does not and MUST NOT transition
  # the tail to JUNK state for pending reuse, because the capabilities we
  # have will have given out originally still span the whole region and so
  # could come to overlap later allocations (if this allocation is not
  # freed, so that they will not be subsets in the revocation test).  A real
  # revoker may wish to scream loudly if it finds capabilities partially
  # overlapping the revocation region (subsuming capabilities are presumably
  # OK, as the allocator holds these).
  #
  def _try_realloc_yes(self, stk, tid, oeva, nsz):
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
      # Don't update the block size, even if it's not a bitmap bucket (which
      # can't be so updated anyway) and don't move anything to JUNK
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
      self._publish('mapd', stk, tid,
                    self._nbucks2sz(bix + self._sz2nbucks(osz)), \
                    self._nbucks2sz(bix + self._sz2nbucks(nsz)), 0b11)
      return True

    return False

  # In-place allocations only if the resulting object is smaller (or no
  # bigger than size rounded up, in terms of bitmap buckets; we don't have
  # the original size to enforce a strict shrinkage policy); see caveat
  # above for why this does not transition any bytes to JUNK.
  def _try_realloc_onlyshrink(self, stk, tid, oeva, nsz):
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

  def _try_realloc_never(self, stk, tid, oeva, nsz):
    # Don't bother with PARANOIA_STATE_PER_OPER since we're just going to
    # call down anyway

    return False

# --------------------------------------------------------------------- }}}
# Rendering ----------------------------------------------------------- {{{

  def occshade(self, szbm) :
    (sz, bm) = szbm

    maxoix = self._maxoix(sz)
    pc = bin(bm).count("1") # XXX YIKES
    i = ceil(256.0 * pc / maxoix) - 1
    return (i << 8) + ((255 - i) << 16)

  def render(self, img) :
    from common.render import renderSpansZ
    from PIL import ImageDraw

    zo = img.width.bit_length() << 1
    basebix = next(loc for (loc, _, _) in self._bix2state)

    # Paint most of the buckets; exclude AHWM since that's big
    renderSpansZ(img, zo,
        ((loc - basebix, sz, bst2color[st])
          for (loc, sz, st) in self._bix2state if st != BuckSt.AHWM))

    # Paint over small WAIT buckets with some occupancy information
    renderSpansZ(img, zo,
        ((bix - basebix, 1, self.occshade(self._bix2szbm[bix]))
          for (loc, sz, st) in self._bix2state
            if st == BuckSt.WAIT
          for bix in range(loc,loc+sz)
            if self._bix2szbm.get(bix,None) is not None
            if self._issmall(self._bix2szbm[bix][0]) ))

    # Paint over the largest revokable span (which may hide some TIDY
    # blocks, but that's fine)
    brss = self._find_largest_revokable_spans(n=1)
    if brss != [] and brss[0][1] is not None :
        renderSpansZ(img, zo, [(brss[0][1] - basebix, brss[0][2], cBRS)])

    # Paint over the oldest JUNK span
    oldestj = self._junklru.first
    if oldestj is not None :
        (qbix, qsz, _) = self._bix2state.get(oldestj.value[0], coalesce_with_values=st_tj)
        renderSpansZ(img, zo, [(qbix - basebix, qsz, cOJS)])

  def _render_expanded(self, img) :
    from common.render import renderSpansZ
    from PIL import ImageDraw

    zo = img.width.bit_length() << 1
    basebix = next(loc for (loc, _, _) in self._bix2state)

    # bix and offset to pixel index
    def expand(bix, off) :
        return (bix * 2**self._bucklog + off + 15) >> 4

    # render a bitmap bucket at block index offset (relative to basebix)
    def rendszbm(bio, ap, sz, bm) :
        ep = self._maxoix(sz)

        if ap is None : ap = ep

        for oix in range(0, ap) :
            renderSpansZ(img, zo,
              [(expand(bio, oix*sz), expand(0, sz*(oix+1)-1) - expand(0, sz*oix),
                bst2color[BuckSt.JUNK] if bm & 1 == 1 else bst2color[BuckSt.WAIT])])
            bm >>= 1

        renderSpansZ(img, zo,
            [(expand(bio, ap*sz), expand(0, sz*ep) - expand(0, sz*ap), bst2color[BuckSt.TIDY])])

    # Paint most of the buckets; exclude AHWM since that's big
    for (loc, sz, st) in self._bix2state:
        # skip AHWM
        if st == BuckSt.AHWM :
            continue
        # JUNK, and TIDY are entirely uniform
        elif st == BuckSt.JUNK :
            renderSpansZ(img, zo, [(expand(loc - basebix, 0), expand(sz, 0), bst2color[st])])
        elif st == BuckSt.TIDY :
            renderSpansZ(img, zo, [(expand(loc - basebix, 0), expand(sz, 0), bst2color[st])])
        # BUMP states are backed at every bix with a bitmap
        elif st == BuckSt.BUMP :
            for bix in range(loc, loc+sz) :
                (asz, bm) = self._bix2szbm[bix]
                rendszbm(bix - basebix, self._szbix2ap[asz].get(bix, None), asz, bm)
        # WAIT states are complicated: they are either backed with a bitmap
        # or by a large value, indicating the uniform occupancy of one or
        # more buckets.  We don't have better resolution than that, so just
        # render those uniformly.
        elif st == BuckSt.WAIT :
            bix = loc
            while bix < loc + sz :
                (asz, bm) = self._bix2szbm[bix]
                if self._issmall(asz) :
                    # bitmap, one bucket
                    rendszbm(bix - basebix, self._szbix2ap[asz].get(bix, None), asz, bm)
                    bix += 1
                else :
                    # large object
                    nsz = self._sz2nbucks(asz)
                    renderSpansZ(img, zo, [(expand(bix - basebix, 0), expand(nsz, 0), bst2color[st])])
                    bix += nsz

# --------------------------------------------------------------------- }}}

# vim: set foldmethod=marker:foldmarker={{{,}}}
