import argparse

from sim.ClingyAllocatorBase import ClingyAllocatorBase

class Allocator(ClingyAllocatorBase):

  __slots__ = ('_bestfit')

  @staticmethod
  def _init_add_args(argp):
    super(__class__, __class__)._init_add_args(argp)
    argp.add_argument('--best-fit', action='store_const',
                      const=True, default=False)

  def _init_handle_args(self, args):
    super()._init_handle_args(args)
    self._bestfit = args.best_fit

  def _alloc_place_small(self, stk, sz, bbks, tidys) :
    try :
        # If there exists an open BUMP bucket, use that
        return next(bbks)
    except StopIteration :
        # Just go grab the first TIDY bucket
        return next(tidys)[0]

  def _alloc_place_large(self, stk, sz, tidys) :
    if self._bestfit :
      (bestloc, bestsz) = (None, None)
      for (loc,tsz) in tidys :
        if tsz < sz : continue      # too small
        if tsz == sz : return loc   # exact fit always best
        if bestsz is not None and bestsz < tsz : continue  # have smaller
        (bestloc, bestsz) = (loc, tsz)
      return bestloc
    else :
      # Just go grab the first TIDY bucket span large enough
      return next(loc for (loc,tsz) in tidys if tsz >= sz)


