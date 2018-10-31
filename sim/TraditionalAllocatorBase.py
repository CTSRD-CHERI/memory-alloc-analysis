#!/usr/bin/env python3

# A dlmalloc-inspired allocator model, with externalized metadata.  All
# allocations are measured in byets, with minimum size 16 bytes and sizes
# always a multiple of 4.
#
# See http://g.oswego.edu/dl/html/malloc.html for more information on
# dmlalloc.

# We use a (simulated, not visible in the heap images) hash table to map
# objects to their state words, rather than imagining them stored in the
# heap.

# Preamble and global parameters -------------------------------------- {{{

from abc import ABCMeta, abstractmethod
import argparse
from bisect import insort
from enum import Enum, unique
import itertools
import logging
from math import ceil
from pyllist import dllist
from sortedcontainers import SortedDict
import sys

from common.intervalmap import IntervalMap
from common.misc import Publisher, dll_im_coalesced_insert
from sim.RenamingAllocatorBase import RenamingAllocatorBase
from sim.SegFreeList import SegFreeList

# Various symbolic names for paranoia levels
PARANOIA_STATE_ON_REVOKE=0
PARANOIA_STATE_PER_OPER=1

# --------------------------------------------------------------------- }}}
# Memory lifecycle definition and prose ------------------------------- {{{

@unique
class SegSt(Enum):
  AHWM = 1 # "wilderness", tidy
  TIDY = 2
  WAIT = 3
  JUNK = 4
  __repr__ = Enum.__str__

sst_atj = { SegSt.AHWM, SegSt.TIDY, SegSt.JUNK }
sst_at  = { SegSt.AHWM, SegSt.TIDY }
sst_tj  = { SegSt.TIDY, SegSt.JUNK }

@unique
class PageSt(Enum):
  UMAP = 1
  MAPD = 2
  __repr__ = Enum.__str__

# Memory is modeled as a series of segments, each in one of the above
# states.  The lifecycle is straightforward:
#
#   Every byte begins in the AHWM "wilderness" state, having never been
#   used.  There are certainly no pointers held to this memory, and no
#   backing frames exist for these pages. ("Above High Water Mark")
#
#   The TIDY state indicates that there are no pointers into this memory,
#   even if it has been used before.
#
#   When an allocation request arrives, we must find a TIDY+AHWM span large
#   enough to contain it and must ensure that the backing page(s) are
#   mapped.  The span is converted to a single segment and marked WAIT.
#
#   When freeing, we transition the whole segment to JUNK.  We may,
#   optionally, unmap any whole pages underlying this free, or may choose to
#   defer unmapping to some later time.
#
#   At some point, we will decide to attempt to reduce our physical memory
#   footprint by unmapping whole pages contained within JUNK (or TIDY)
#   segments.  Also at some point, we will decide to begin reusing virtual
#   address space, engaging in revocation, transitioning spans back to
#   TIDY segments for subsequent reallocation.

# This allocator maintains two linked lists: a collection of JUNK spans, for
# use with revocation, and an explicit free list of TIDY spans.  The latter
# turns out to be vital for runtime performance, as we, unlike Clingy
# allocators, operate on individual objects, of which there are very many,
# and so linear scans through the state intervalmap to find TIDY regions is
# not really tenable.

# --------------------------------------------------------------------- }}}

class TraditionalAllocatorBase(RenamingAllocatorBase):
# Initialization ------------------------------------------------------ {{{

  __slots__ = (
    '_alignlog', # Power of two default alignment
    '_alignmsk', # Derived alignment mask
    '_minsize' , # Minimum allocation size
    '_paranoia', # Self-tests
    '_revoke_k', # Number of regions to simultaneously revoke

    '_tslam'   , # fetch the current trace timestamp

    '_basepg'  , # Bottom-most page index to use

    '_brscache', # cached biggest revokable span
    '_eva2sst' , # Emulated Virtual Address to Segment STate
    '_eva2sz'  , # EVA to size for outstanding allocations (WAIT states)
    '_evp2pst' , # Emulated Virtual Page to Page STate
    '_junklru' , # LRU queue of JUNK segments, by base address
    '_junkadn' , # JUNK segment base EVA to node in junklru
    '_njunk'   , # Number of bytes JUNK
    '_nmapped' , # Number of bytes MAPD
    '_nwait'   , # Number of bytes WAIT (allocated)
    '_pagelog' , # Base-2 log of page size
    '_tidylst' , # SegFreeList of TIDY spans
    '_wildern'   # Wilderness location
  )

  __metaclass__ = ABCMeta

# Argument definition and response ------------------------------------ {{{
  @staticmethod
  def _init_add_args(argp) :
    argp.add_argument('--paranoia', action='store', type=int, default=0)
    argp.add_argument('--revoke-k', action='store', type=int, default=16)
    argp.add_argument('--min-size', action='store', type=int, default=16)
    argp.add_argument('--align-log', action='store', type=int, default=2)
    argp.add_argument('--unsafe-reuse', action='store_const', const=True,
                      default=False,
                      help='free immediately to reusable state')

  def _init_handle_args(self, args) :
    self._alignlog        = args.align_log
    self._alignmsk        = (1 << args.align_log) - 1

    self._minsize         = args.min_size
    if args.unsafe_reuse :
      self._free = self._free_unsafe

    self._paranoia        = args.paranoia
    if self._paranoia == 0 and __debug__ :
        logging.warn("Assertions still enabled, even with paranoia 0; "
                     "try python -O")
    if self._paranoia != 0 and not __debug__ :
        raise ValueError("Paranoia without assertions will just be slow")

    assert args.revoke_k > 0
    self._revoke_k        = args.revoke_k

# --------------------------------------------------------------------- }}}

  def __init__(self, **kwargs) :
    super().__init__()
    self._tslam = kwargs['tslam']
    self._paranoia = 0

# Argument parsing ---------------------------------------------------- {{{

    argp = argparse.ArgumentParser()
    self._init_add_args(argp)
    self._init_handle_args(argp.parse_args(kwargs['cliargs']))

# --------------------------------------------------------------------- }}}

    self._pagelog  = 12
    self._basepg = 1
    baseva = self._basepg * 2**self._pagelog

    self._brscache = None
    self._eva2sst  = IntervalMap(baseva, 2**64 - baseva, SegSt.AHWM)
    self._eva2sz   = {}
    self._evp2pst  = IntervalMap(self._basepg,
                      2**(64 - self._pagelog) - self._basepg, PageSt.UMAP)
    self._junklru  = dllist()
    self._junkadn  = {}
    self._njunk    = 0
    self._nmapped  = 0
    self._nwait    = 0
    self._tidylst  = SegFreeList()
    self._wildern  = baseva

# --------------------------------------------------------------------- }}}
# Size-related utility functions -------------------------------------- {{{

  def _eva2evp(self, eva) : return eva >> self._pagelog
  def _evp2eva(self, evp) : return evp << self._pagelog

  def _eva2evp_roundup(self, eva) :
    return (eva + (1 << self._pagelog) - 1) >> self._pagelog

  def _npg2nby(self, npg) : return npg << self._pagelog

# --------------------------------------------------------------------- }}}
# Additional state assertions and diagnostics ------------------------- {{{

  def _state_asserts(self) :

    # Ensure that our wilderness looks like the HWM
    (qbase, qsz, qv) = self._eva2sst[self._wildern]
        # "I'm sure it's around here somewhere"
    assert qbase + qsz == 2**64, ("wilderness lost", self._wildern, qbase, qsz, qv)
        # "no longer above high water mark"
    assert qv == SegSt.AHWM, ("wilderness flooded", self._wildern, qbase, qsz, qv)

    # All outstanding allocations are backed by WAIT and MAPD segments, yes?
    for a in self._eva2sz.keys() :
      (qbase, qsz, qv) = self._eva2sst[a]
      assert qv == SegSt.WAIT, ("rude allocation", a, qv) # not WAITing
        # segment too short for allocation
      assert qbase + qsz >= a + self._eva2sz[a], ("alloc overflow", a)

      (qbase, qsz, qv) = self._evp2pst[self._eva2evp(a)]
      assert qv == PageSt.MAPD, ("lost allocation", a, qv) # "un-mapped"
      assert self._evp2eva(qbase) + self._npg2nby(qsz) >= a + self._eva2sz[a],\
        ("partially lost allocation", a, self._eva2sz[a], qbase, qsz)

    # All JUNK queue entries are backed by JUNK segments
    for (jb, jsz) in self._junklru :
      (qb, qsz, qv) = self._eva2sst[jb]
      assert jb == qb and jsz == qsz and qv == SegSt.JUNK, \
             ("JUNK list state mismatch", (jb, jsz), (qb, qsz, qv))
      assert jb in self._junkadn, "JUNK node not in index"
      assert (jb, jsz) == self._junkadn[jb].value, "JUNK index botch"

    for jb in self._junkadn :
      assert self._junkadn[jb].value[0] == jb
      jsz = self._junkadn[jb].value[1]
      (qb, qsz, qv) = self._eva2sst[jb]
      assert jb == qb and jsz == qsz and qv == SegSt.JUNK, \
             ("JUNK list state mismatch", (jb, jsz), (qb, qsz, qv))

    # All TIDY list entries are backed by TIDY segments, and the SegFL is OK
    for (tb, tsz) in self._tidylst.iterlru() :
      (qb, qsz, qv) = self._eva2sst[tb]
      assert tb == qb and tsz == qsz and qv == SegSt.TIDY, \
             ("TIDY list state mismatch", (tb, tsz), (qb, qsz, qv))

    self._tidylst.crossreference_asserts()

    # All WAIT spans are covered by allocations, all JUNK and TIDY spans
    # correspond with entries in their queues
    nwait = 0
    njunk = 0
    for (qb, qsz, qv) in self._eva2sst :
      if qv == SegSt.WAIT :
        nwait += qsz
        ab = qb
        while ab < qb + qsz :
          asz = self._eva2sz.get(ab, None)
          assert asz is not None, ("WAIT w/o alloc sz", qb, ab)
          ab += asz
      elif qv == SegSt.TIDY :
        assert qsz == self._tidylst.peek(qb)
      elif qv == SegSt.JUNK :
        njunk += qsz
        dln = self._junkadn.get(qb,None)
        assert dln is not None
        assert dln.value == (qb, qsz)
      elif qv == SegSt.AHWM :
        assert qb == self._wildern, "There must be only one final frontier"
    assert nwait == self._nwait, ("Improper account of WAIT bytes", nwait, self._nwait)
    assert njunk == self._njunk, ("Improper account of JUNK bytes", njunk, self._njunk)

    # All MAPD segments have some reason to be mapped?  Well, maybe not
    # exactly, since we are lazy about unmapping, or might be.
    #
    ## for (mb, msz, mv) in self._eva2pst :
    ##     if mv != PageSt.MAPD : continue
    ##     for (qb, qsz, qv) in self._eva2sst[mb:mb+msz] :
    ##         if qv == SegSt.WAIT : break
    ##     else : assert False, ("MAPD w/o WAIT", mb, msz)

# --------------------------------------------------------------------- }}}
# Revocation logic ---------------------------------------------------- {{{

  # Mark a span TIDY.  This must not be used to re-mark any existing TIDY
  # span.
  #
  # Inserts the coalesced span at the end of tidylst.
  def _mark_tidy(self, loc, sz):
      self._eva2sst.mark(loc, sz, SegSt.TIDY)
      (cva, csz, _) = self._eva2sst[loc]
      self._tidylst.insert_coalesced(loc, sz, cva, csz)

  # An actual implementation would maintain a prioqueue or something;
  # we can get away with a linear scan.  We interrogate the segment state
  # interval map for ease of coalescing, even though we also maintain a
  # parallel JUNK LRU queue
  def _find_largest_revokable_spans(self, n=1):
    if n == 0 : return
    if n == 1 and self._brscache is not None :
        return [self._brscache]

    bests = [(0, -1, -1)] # [(njunk, loc, sz)] in ascending order
    cursorloc = next(loc for (loc, _, _) in self._eva2sst)
    while cursorloc < self._wildern :
        # Exclude AHWM, which is like TIDY but would almost always be biggest
        (qbase, qsz, qv) = self._eva2sst.get(cursorloc,
                            coalesce_with_values=sst_tj)
        assert (qbase == cursorloc) or (qv not in sst_tj), \
           ("JUNK hunt index", qbase, cursorloc, qv, qsz, list(self._eva2sst))
        # Advance cursor now so we can just continue in the below tests
        # Note that this is not a straight sum because we could have
        # coalesced backwards.  In that case, we are about to bounce out
        # of this iteration with the qv sst_tj check.
        cursorloc = qbase + qsz

        # Smaller or busy spans don't interest us
        if qsz <= bests[0][0] : continue
        if qv not in sst_tj : continue

        # Reject spans that are entirely TIDY already.
        js = [sz for (_, sz, v) in self._eva2sst[qbase:qbase+qsz]
                  if v == SegSt.JUNK]
        if js == [] : continue

        # Sort spans by number of JUNK buckets, not JUNK|TIDY buckets
        nj = sum(js)
        if nj <= bests[0][0] : continue
        insort(bests, (nj, qbase, qsz))

        bests = bests[(-n):]

    return [best for best in bests if best[1] >= 0]

  def _do_revoke(self, ss) :
   if self._paranoia > PARANOIA_STATE_ON_REVOKE : self._state_asserts()

   self._brscache = None

   for (nj, loc, sz) in ss :
    self._njunk -= nj
    # Because we coalesce with TIDY spans while revoking, there may be
    # several JUNK spans in here.  Go remove all of them from the LRU.
    for (qb, qsz, qv) in self._eva2sst[loc:loc+sz] :
      assert qv in sst_tj, "Revoking non-revokable span"
      if qv == SegSt.JUNK :
        self._junklru.remove(self._junkadn.pop(qb))
        self._mark_tidy(qb, qsz)

   self._publish('revoked', "---", "", [(loc, loc+sz) for (_, loc, sz) in ss])

  def _do_revoke_best_and(self, n=None, revoke=[]) :

    revs = list(revoke)
    assert len(revs) <= self._revoke_k, (revoke)

    if n is None :
        n = self._revoke_k

    nrev = None
    brss = self._find_largest_revokable_spans(n=n+1)

    rset = set()
    for rloc in revs :
      for (brnj, brloc, brsz) in brss :
        if brloc <= rloc < brloc + brsz :
          rset.add((brnj, brloc, brsz))
          break
      else :
        (qloc, qsz, qv) = self._eva2sst.get(rloc, coalesce_with_values=sst_tj)
        rset.add( (sum([sz for (_,sz,v) in self._eva2sst[qloc:qloc+qsz]
                            if v == SegSt.JUNK]),
                   qloc, qsz) )
    while len(rset) <= n and brss != [] :
      rset.add(brss[-1])
      brss = brss[:-1]

    while brss != [] :
      if brss[-1] not in rset : break
      brss = brss[:-1]
    if brss != [] : self._brscache = brss[-1]
    else          : self._brscache = (0, -1, -1)

    self._do_revoke(rset)

  @abstractmethod
  def _maybe_revoke(self):
    pass

# --------------------------------------------------------------------- }}}
# Allocation ---------------------------------------------------------- {{{

  def _alloc_place(self, stk, sz) :
    # XXX Approximate best-fit / oldest-fit strategy, since coalesced
    # entries are moved to the back of the tidy list.  A segregated free
    # list would probably improve modeling time performance dramatically.
    #
    # Note the requirement to either fit exactly or leave at least 16 bytes
    # free.
    try :
      return next(self._tidylst.iterfor(sz, 16))[0]
    except StopIteration :
      return self._wildern

  def _ensure_mapped(self, stk, tid, reqbase, reqsz) :
    pbase = self._eva2evp(reqbase)
    plim  = self._eva2evp(reqbase + reqsz - 1)
    for (qb, qsz, qv) in self._evp2pst[pbase:plim] :
      if qv == PageSt.MAPD : continue
      if qb + qsz > plim : qsz = plim - qb
      self._nmapped += self._npg2nby(qsz)
      self._publish('mapd', stk, tid, self._evp2eva(qb), self._evp2eva(qb + qsz), 0b11)
    self._evp2pst.mark(pbase, plim-pbase+1, PageSt.MAPD)

  def _mark_allocated(self, reqbase, reqsz) :
    if self._paranoia > PARANOIA_STATE_PER_OPER:
      (qbase, qsz, qv) = self._eva2sst.get(reqbase, coalesce_with_values=sst_at)
      assert qv in sst_at, ("New allocated mark in bad state", \
        (reqbase, reqsz), (qbase, qsz, qv), list(self._eva2sst))
      assert qbase + qsz >= reqbase + reqsz, "New allocated undersized?"

    # Homesteading beyond the wildnerness frontier leaves a TIDY gap
    if reqbase > self._wildern :
      self._mark_tidy(self._wildern, reqbase - self._wildern)

    # Remove span from tidy list; may create two more entries.
    # No need to use the coalescing insert functionality here because we
    # know, inductively, that we certainly won't coalesce in either direction.
    #
    # XXX We act as though any residual spans have been just created; is
    # that the right policy?
    #
    # XXX Don't create segments less than the minimum allocation size, as
    # there's no possible utility to them and we'll catch them
    # post-coalescing in mark_tidy.  This change will require modification
    # to our asserts and sanity checking, too.
    if reqbase < self._wildern:
      (qb, qsz, qv) = self._eva2sst[reqbase]
      assert qv == SegSt.TIDY
      assert qsz >= reqsz
      tsz = self._tidylst.remove(qb)
      assert tsz == qsz
      if qb + qsz != reqbase + reqsz :
        # Insert residual right span
        self._tidylst.insert(reqbase+reqsz, qb+qsz-reqbase-reqsz)
      if reqbase != qb :
        # Insert residual left span
        self._tidylst.insert(qb, reqbase-qb)

    # If the allocation takes place within the current best revokable span,
    # invalidate the cache and let the revocation heuristic reconstruct it.
    if self._brscache is not None :
      (_, brsix, brssz) = self._brscache
      if brsix <= reqbase < brsix + brssz :
        self._brscache = None

    self._nwait += reqsz
    self._wildern = max(self._wildern, reqbase + reqsz)
    self._eva2sst.mark(reqbase, reqsz, SegSt.WAIT)

  def _alloc(self, stk, tid, sz) :
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()

    if sz < self._minsize : sz = self._minsize   # minimum size
    sz = (sz + self._alignmsk) & ~self._alignmsk # and alignment

    loc = self._alloc_place(stk, sz)

    self._ensure_mapped(stk,tid,loc,sz)
    self._mark_allocated(loc,sz)
    self._eva2sz[loc] = sz
    return loc

# --------------------------------------------------------------------- }}}
# Free ---------------------------------------------------------------- {{{

  def _ensure_unmapped(self, stk, tid, loc, sz):
    pbase = self._eva2evp_roundup(loc)
    plim  = self._eva2evp(loc + sz - 1)
    if pbase == plim : return # might not be an entire page

    for (qb, qsz, qv) in self._evp2pst[pbase:plim] :
      if qv == PageSt.UMAP : continue
      self._nmapped -= self._npg2nby(qsz)
      self._publish('unmapd', stk, tid, self._evp2eva(qb), self._evp2eva(qb + qsz))
    self._evp2pst.mark(pbase, plim-pbase, PageSt.UMAP)


  def _free(self, stk, loc):
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()
    assert self._eva2sst[loc][2] == SegSt.WAIT, "free non-WAIT?"

    # Mark this span as junk
    sz = self._eva2sz.pop(loc)
    self._eva2sst.mark(loc, sz, SegSt.JUNK)
    self._nwait -= sz
    self._njunk += sz

    # If it happens that this span may be larger than the cached largest
    # revokable span, invalidate the cache
    if self._brscache is not None :
      (brsnj, _, _) = self._brscache
      (_, qsz, _) = self._eva2sst.get(loc, coalesce_with_values=sst_tj)
      if qsz >= brsnj :
        self._brscache = None

    # Update the JUNK LRU
    (qb, qsz) = dll_im_coalesced_insert(loc,sz,self._eva2sst,self._junklru,self._junkadn)

    # If the JUNK span is large enough, go ensure that it is unmapped, save
    # possibly for some material on either side.
    # XXX configurable policy
    if qsz > (16 * 2**self._pagelog) :
      self._ensure_unmapped(stk, qb, qsz)

    self._maybe_revoke()

  def _free_unsafe(self, stk, loc):
    if self._paranoia > PARANOIA_STATE_PER_OPER : self._state_asserts()
    assert self._eva2sst[loc][2] == SegSt.WAIT, "free non-WAIT?"

    # Immediately mark this span as TIDY, rather than JUNK
    sz = self._eva2sz.pop(loc)
    self._nwait -= sz
    self._mark_tidy(loc, sz)

    # If the present TIDY span is quite large, go ahead and do an unmap
    # XXX configurable policy
    (qb, qsz, qv) = self._eva2sst.get(loc)
    assert qv == SegSt.TIDY
    if qsz > (16 * 2**self._pagelog) :
      self._ensure_unmapped(stk, qb, qsz)

# --------------------------------------------------------------------- }}}
# Realloc ------------------------------------------------------------- {{{

  def _try_realloc(self, stk, tid, oeva, nsz):
    # XXX
    return False

# --------------------------------------------------------------------- }}}
# Rendering ----------------------------------------------------------- {{{

  def render(self, img) :
    from common.render import renderSpansZ
    from PIL import ImageDraw

    sst2color = {
      SegSt.TIDY : 0xFFFFFF,
      SegSt.WAIT : 0x00FF00,
      SegSt.JUNK : 0xFF0000,
    }

    baseva = self._basepg * 2**self._pagelog

    zo = img.width.bit_length() << 1

    renderSpansZ(img, zo,
      (((loc - baseva) >> self._alignlog, sz >> self._alignlog, sst2color[st])
        for (loc, sz, st) in self._eva2sst.irange(baseva,self._wildern)))

    # Paint over the oldest JUNK span
    oldestj = self._junklru.first
    if oldestj is not None :
        (qb, qsz) = oldestj.value
        qb -= baseva
        renderSpansZ(img, zo, [(qb >> self._alignlog, qsz >> self._alignlog, 0xFF00FF)])

    # Paint over the oldest TIDY span
    oldestt = self._tidylst.eldest()
    if oldestt is not None :
        (qb, qsz) = oldestt
        qb -= baseva
        renderSpansZ(img, zo, [(qb >> self._alignlog, qsz >> self._alignlog, 0x00FFFF)])


# --------------------------------------------------------------------- }}}



# vim: set foldmethod=marker:foldmarker={{{,}}}
