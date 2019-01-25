#!/usr/bin/env python3

# Not really an allocator model, but fits in the same approximate logical
# space.  Warns about and optionally fixes some aspects of a trace.
# Specifically:
#
#   Overlapping allocations (allocation of allocated space)
#   Allocation of unmapped space
#
#   Revocation of allocated space
#   Free of {free/revoked} space
#
#   Mapping of mapped space
#   Unmapping of unmapped space
#   Unmapping of allocated space

# Preamble ------------------------------------------------------------ {{{

import argparse
import logging

from intervaltree import IntervalTree

from common.misc import Publisher
from common.misc import AddrIval
from common.misc import AddrIvalState as AState

if __name__ == "__main__" and __package__ is None:
  import os
  sys.path.append(os.path.dirname(sys.path[0]))

# --------------------------------------------------------------------- }}}
class Allocator(Publisher):
# Initialization ------------------------------------------------------ {{{

  __slots__ = ('_aa', '_am', '_arg', '_ts')

  def __init__(self, tslam=None, cliargs=[], **kwargs):
    super().__init__()

    self._ts = tslam

    self._aa = IntervalTree()
    self._aa.add(AddrIval(0, 2**64, AState.REVOKED))

    self._am = IntervalTree()
    self._am.add(AddrIval(0, 2**64, AState.UNMAPD))

    self._ls = {}

# Argument parsing ---------------------------------------------------- {{{

    argp = argparse.ArgumentParser()
    argp.add_argument('--fix',
                      action='store_const', const=True, default=False,
                      help="Automatically insert fixups for reports")
    argp.add_argument('--skip-map',
                      action='store_const', const=True, default=False,
                      help="Ignore map/unmap constraints")
    argp.add_argument('--drop-safe',
                      action='store_const', const=True, default=False,
                      help="Suppress warnings for safely dropped events")
    self._arg = argp.parse_args(cliargs)

# --------------------------------------------------------------------- }}}
# --------------------------------------------------------------------- }}}
# Allocation ---------------------------------------------------------- {{{

  def _allocd(self, begin, end):
    overlaps_a = self._aa[begin:end]
    overlaps_m = self._am[begin:end]

    if not self._arg.skip_map :
      overlaps_unmapped = [o for o in overlaps_m if o.state == AState.UNMAPD]
      if overlaps_unmapped:
        logging.warning("Allocation ts=%d b=%x e=%x overlaps unmap=%r",
          self._ts(), begin, end, overlaps_unmapped)

      # XXX fix by mapping pages

    overlaps_allocated = [o for o in overlaps_a if o.state == AState.ALLOCD]
    if overlaps_allocated:
      logging.error("Allocation ts=%d b=%x e=%x overlaps alloc=%r",
        self._ts(), begin, end, overlaps_allocated)
      if self._arg.fix :
        for oa in overlaps_allocated :
          self._publish('free', '', oa.begin)

    self._aa.chop(begin,end)
    self._aa.add(AddrIval(begin,end,AState.ALLOCD))

  def allocd(self, stk, begin, end):
    self._allocd(begin, end)
    self._publish('allocd', stk, begin, end)
  
# --------------------------------------------------------------------- }}}
# Freeing ------------------------------------------------------------- {{{

  def _freed(self, addr):
    doalloc = False
    end = addr+1 # Will be fixed up later
    overlaps_a = self._aa[addr:end]
    overlaps_m = self._am[addr:end]

    if not self._arg.skip_map :
      overlaps_unmapped = [o for o in overlaps_m if o.state == AState.UNMAPD]
      if overlaps_unmapped:
        logging.error("Free ts=%d a=%x overlaps unmap=%r",
                      self._ts(), addr, overlaps_unmapped)

    allocations = [o for o in overlaps_a if o.state == AState.ALLOCD]
    overlaps_free = [o for o in overlaps_a if o.state == AState.FREED]
    if overlaps_free != []:
      logging.warning("Free ts=%d a=%x overlaps free=%r",
                        self._ts(), addr, overlaps_free)
      if allocations == [] and len(overlaps_free) == 1 and self._arg.drop_safe :
        return False
      else :
        for of in overlaps_free :
          if of.begin <= addr :
            end = max(end, of.end)
        if self._arg.fix :
          doalloc = True

    if len(allocations) > 1 or (allocations != [] and overlaps_free != []) :
        logging.error("Free ts=%d a=%x multiply-attested alloc=%r free=%r",
                      self._ts(), addr, allocations, overlaps_free)
    elif allocations == [] and overlaps_free == [] :
      logging.warning("Free ts=%d a=%x no corresponding alloc",
          self._ts(), addr)
      if self._arg.fix and not self._arg.drop_safe:
        doalloc = True
      else : 
        assert doalloc == False
        return False
    else :
      for a in allocations:
        if a.begin != addr :
          # Likely to leave cruft behind, indicative of serious errors
          logging.error("Free ts=%d a=%x within alloc=%r",
                        self._ts(), addr, a)
        else :
          end = max(end, a.end)

    self._aa.chop(addr, end)
    self._aa.add(AddrIval(addr, end, AState.FREED))

    if doalloc:
      self._publish('allocd', '', addr, end)

    return True

  def freed(self, stk, addr):
    if addr == 0 :
        # Just throw out free(NULL)
        return

    if self._freed(addr) :
      self._publish('freed', stk, addr)
  
# --------------------------------------------------------------------- }}}
# Reallocation -------------------------------------------------------- {{{

  def reallocd(self, stk, begin_old, begin_new, end_new):
    self._freed(begin_old)
    self._allocd(begin_new, end_new)
    self._publish('reallocd', stk, begin_old, begin_new, end_new)

# --------------------------------------------------------------------- }}}
# Mapping ------------------------------------------------------------- {{{

  def mapd(self, stk, begin, end, prot):

    # XXX

    self._publish('mapd', stk, begin, end, prot)
  
# --------------------------------------------------------------------- }}}
# Unmapping ----------------------------------------------------------- {{{

  def unmapd(self, stk, begin, end):

    # XXX

    self._publish('unmapd', stk, begin, end)
  
# --------------------------------------------------------------------- }}}
# Revoking ------------------------------------------------------------ {{{

  def revoked(self, stk, spans):

    for (begin,end) in spans:
      overlaps = self._aa[begin:end]
      overlaps_allocated = [o for o in overlaps if o.state == AState.ALLOCD]
      if overlaps_allocated:
        logging.warning("Revocation ts=%d b=%x e=%x overlaps alloc=%r",
          self._ts(), begin, end, overlaps_allocated)
        if self._arg.fix :
          for oa in overlaps_allocated :
            self._publish('free', '', oa.begin)

        # XXX fix by freeing

    self._publish('revoked', stk, spans)
  
# --------------------------------------------------------------------- }}}
# Size-measurement pass-thru ------------------------------------------ {{{

  def aspace_sampled(self, event, size, sweep_size):
    self._publish('aspace_sampled', event, size, sweep_size)

# --------------------------------------------------------------------- }}}

# vim: set foldmethod=marker:foldmarker={{{,}}}
