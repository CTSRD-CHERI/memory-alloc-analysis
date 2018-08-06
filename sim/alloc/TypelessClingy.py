from sim.ClingyAllocatorBase import ClingyAllocatorBase

class Allocator(ClingyAllocatorBase):

  def _alloc_place_small(self, stk, bbks, tidys) :
    try :
        # If there exists an open BUMP bucket, use that
        return next(bbks)
    except StopIteration :
        # Just go grab the first TIDY bucket
        return next(tidys)[0]

  def _alloc_place_large(self, sz, stk, tidys) :
    # Just go grab the first TIDY bucket span large enough
    return next(loc for (loc,tsz) in tidys if tsz >= sz)


