#!/usr/bin/env python3

# Extract a random, but coherent, subset of a trace.  That is, we will never
# emit an event for an object we've decided not to allocate in the generated
# trace.
#
# Adjust --screw from 0 (all objects rejected) to 256 (all objects pass).  Use
# multiple passes, perhaps with with different --seeds, to further winnow.

import argparse
import marshal
from common.misc import Publisher

class Allocator (Publisher):
  __slots__ = ('_allocix', '_screw', '_seed', '_shadows')

  def __init__(self, **kwargs):
    super().__init__()
    self._allocix = 0
    self._shadows = set()

    argp = argparse.ArgumentParser()
    argp.add_argument('--screw', action='store', type=int, default=128,
                      help='The thing one turns')
    argp.add_argument('--seed', action='store', default='abracadabra')
    args = argp.parse_args(kwargs['cliargs'])
    self._screw   = args.screw
    self._seed    = args.seed

  def allocd(self, stk, tid, begin, end):
    h = hash(marshal.dumps([self._seed, self._allocix, begin]))
    if (h % 256 >= self._screw) :
        self._shadows.add(begin)
        return
    self._publish('allocd', stk, tid, begin, end)

  def freed(self, stk, tid, va):
    if va in self._shadows :
        self._shadows.remove(va)
        return
    self._publish('freed', stk, tid, va)

  def reallocd(self, stk, tid, ova, nva, nend):
    if ova in self._shadows :
        self._shadows.remove(ova)
        self._shadows.add(nva)
        return
    self._publish('reallocd', stk, tid, ova, nva, nend)
        
  # Pass through
  def size_measured(self, sz):
    self._publish('size_measured', sz)

  def sweep_size_measured(self, sz):
    self._publish('sweep_size_measured', sz)

  def mapd(self, stk, tid, begin, end, prot):
    self._publish('mapd', stk, tid, begin, end, prot)

  def unmapd(self, stk, tid, begin, end):
    self._publish('unmapd', stk, tid, begin, end)

  def revoked(self, stk, tid, spans):
    self._publish('revoked', stk, tid, spans)
