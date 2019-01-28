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

  def allocd(self, event, begin, end):
    h = hash(marshal.dumps([self._seed, self._allocix, begin]))
    if (h % 256 >= self._screw) :
        self._shadows.add(begin)
        return
    self._publish('allocd', event, begin, end)

  def freed(self, event, va):
    if va in self._shadows :
        self._shadows.remove(va)
        return
    self._publish('freed', event, va)

  def reallocd(self, event, ova, nva, nend):
    if ova in self._shadows :
        self._shadows.remove(ova)
        self._shadows.add(nva)
        return
    self._publish('reallocd', event, ova, nva, nend)
        
  # Pass through
  def aspace_sampled(self, event, size, sweep_size):
    self._publish('aspace_sampled', event, size, sweep_size)

  def mapd(self, event, begin, end, prot):
    self._publish('mapd', event, begin, end, prot)

  def unmapd(self, event, begin, end):
    self._publish('unmapd', event, begin, end)

  def revoked(self, event, spans):
    self._publish('revoked', event, spans)
