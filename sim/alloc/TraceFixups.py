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
from enum import Enum, unique
import logging

from intervaltree import Interval, IntervalTree

from common.misc import Publisher

if __name__ == "__main__" and __package__ is None:
  import os
  sys.path.append(os.path.dirname(sys.path[0]))

# --------------------------------------------------------------------- }}}
# State classes ------------------------------------------------------- {{{
@unique
class VAState(Enum):
  ALLOCD  = 1
  FREED   = 2
  REVOKED = 3

  __repr__ = Enum.__str__

@unique
class VMState(Enum):
  MAPD  = 1
  UNMAPD  = 2

  __repr__ = Enum.__str__

class AddrInterval(Interval):
  __slots__ = ()

  def __new__(cls, begin, end, state):
    return super().__new__(cls, begin, end, state)

  @property
  def state(self):
    return self.data

  def __repr__(self):
    r = super().__repr__()
    r = r.replace('Interval', __class__.__name__, 1)
    r = r.replace(str(self.begin), hex(self.begin)[2:])
    r = r.replace(str(self.end), hex(self.end)[2:])
    return r

  __str__ = __repr__


# --------------------------------------------------------------------- }}}
class Allocator(Publisher):
# Initialization ------------------------------------------------------ {{{

  __slots__ = ('_aa', '_am', '_arg', '_ts')

  def __init__(self, tslam=None, cliargs=[], **kwargs):
    super().__init__()

    self._ts = tslam

    self._aa = IntervalTree()
    self._aa.add(AddrInterval(0, 2**64, VAState.REVOKED))

    self._am = IntervalTree()
    self._am.add(AddrInterval(0, 2**64, VMState.UNMAPD))

    self._ls = {}

# Argument parsing ---------------------------------------------------- {{{

    argp = argparse.ArgumentParser()
    argp.add_argument('--fix',
                      action='store_const', const=True, default=False,
                      help="Automatically insert fixups for reports")
    argp.add_argument('--skip-map',
                      action='store_const', const=True, default=False,
                      help="Ignore map/unmap constraints")
    self._arg = argp.parse_args(cliargs)

# --------------------------------------------------------------------- }}}
# --------------------------------------------------------------------- }}}
# Allocation ---------------------------------------------------------- {{{

  def _allocd(self, begin, end):
    overlaps_a = self._aa[begin:end]
    overlaps_m = self._am[begin:end]

    overlaps_unmapped = [o for o in overlaps_m if o.state == VMState.UNMAPD]

    if not self._arg.skip_map and overlaps_unmapped:
      logging.warning("Allocation ts=%d b=%x e=%x overlaps unmap=%r",
        self._ts(), begin, end, overlaps_unmapped)

      # XXX fix by mapping pages

    overlaps_allocated = [o for o in overlaps_a if o.state == VAState.ALLOCD]
    if overlaps_allocated:
      logging.error("Allocation ts=%d b=%x e=%x overlaps alloc=%r",
        self._ts(), begin, end, overlaps_allocated)

      # XXX fix by freeing

    self._aa.chop(begin,end)
    self._aa.add(AddrInterval(begin,end,VAState.ALLOCD))

  def allocd(self, stk, begin, end):
    self._allocd(begin, end)
    self._publish('allocd', stk, begin, end)
  
# --------------------------------------------------------------------- }}}
# Freeing ------------------------------------------------------------- {{{

  def _freed(self, addr):
    end = addr+1 # Will be fixed up later
    overlaps_a = self._aa[addr:end]
    overlaps_m = self._am[addr:end]

    overlaps_unmapped = [o for o in overlaps_m if o.state == VMState.UNMAPD]
    if not self._arg.skip_map and overlaps_unmapped:
      logging.error("Free ts=%d a=%x overlaps unmap=%r",
                    self._ts(), addr, overlaps_unmapped)

    overlaps_free = [o for o in overlaps_a if o.state == VAState.FREED]
    if overlaps_free:
      logging.warning("Free ts=%d a=%x overlaps free=%r",
                      self._ts(), addr, overlaps_free)
      for of in overlaps_free :
        if of.begin == addr :
          end = max(end, of.end)
      if self._arg.fix :
        self._publish('allocd', addr, end)

    allocations = [o for o in overlaps_a if o.state == VAState.ALLOCD]
    if len(allocations) > 1 or (allocations != [] and overlaps_free != []) :
        logging.error("Free ts=%d a=%x multiply-attested alloc=%r free=%r",
                      self._ts(), addr, allocations, overlaps_free)
    elif allocations == [] and overlaps_free == [] :
      logging.warning("Free ts=%d a=%x no corresponding alloc",
        self._ts(), addr)
      if self._arg.fix :
        self._publish('allocd', addr, end)
    else :
      for a in allocations:
        if a.begin != addr :
          # Likely to leave cruft behind, indicative of serious errors
          logging.error("Free ts=%d a=%x within alloc=%r",
                        self._ts(), addr, a)
        else :
          end = max(end, a.end)

    self._aa.chop(addr, end)
    self._aa.add(AddrInterval(addr, end, VAState.FREED))

  def freed(self, stk, addr):
    self._freed(addr)
    self._publish('freed', stk, addr)
  
# --------------------------------------------------------------------- }}}
# Reallocation -------------------------------------------------------- {{{

  def reallocd(self, stk, begin_old, begin_new, end_new):
    self._freed(begin_old)
    self._allocd(begin_new, end_new)
    self._publish('reallocd', stk, begin_old, begin_new, end_new)

# --------------------------------------------------------------------- }}}
# Mapping ------------------------------------------------------------- {{{

  def mapd(self, stk, begin, end):

    # XXX

    self._publish('mapd', stk, begin, end)
  
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
      overlaps_allocated = [o for o in overlaps if o.state == VAState.ALLOCD]
      if overlaps_allocated:
        logging.warning("Revocation ts=%d b=%x e=%x overlaps alloc=%r",
          self._ts(), begin, end, overlaps_allocated)

        # XXX fix by freeing

    self._publish('revoked', stk, spans)
  
# --------------------------------------------------------------------- }}}
# Size-measurement pass-thru ------------------------------------------ {{{

  def size_measured(self, sz):
    self._publish('size_measured', sz)

  def sweep_size_measured(self, sz):
    self._publish('sweep_size_measured', sz)

# --------------------------------------------------------------------- }}}

# vim: set foldmethod=marker:foldmarker={{{,}}}
