import argparse
from zlib import adler32

from sim.alloc.TypelessClingy import Allocator as TCA

# Override the typeless clingy allocator's small placement policy using a
# simple random hash function of the stack.
class Allocator(TCA):

  __slots__ = (
     '_bb2hash',
     '_hashmask',
  )

  @staticmethod
  def _init_add_args(argp):
    super(__class__,__class__)._init_add_args(argp)
    argp.add_argument('--hashlog', action='store', type=int, default=4)

  def _init_handle_args(self, args):
    super(__class__,self)._init_handle_args(args)
    self._hashmask = ((1 << args.hashlog) - 1)
    self._bb2hash = {}

  def _alloc_place_small(self, stk, sz, bbks, tidys) :
    h = adler32(stk.encode()) & self._hashmask
    for bbk in bbks :
        if self._bb2hash[bbk] == h : return bbk

    # Go claim a block; if bestfit, will be the smallest available
    # block, to help more densely pack small object buckets.
    bbk = self._alloc_place_large(stk, 1, tidys)
    self._bb2hash[bbk] = h
    return bbk

  def _alloc_place_small_full(self, bbk) :
    del self._bb2hash[bbk]
