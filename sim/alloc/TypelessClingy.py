import argparse
import itertools

from sim.ClingyAllocatorBase import ClingyAllocatorBase

class Allocator(ClingyAllocatorBase):

  __slots__ = (
     '_lastrevt',
     '_overhead_factor',
     '_rev_lru',
     '_revoke_t',
     '_rev_tidy_factor',
     '_tidy_factor',
  )

  @staticmethod
  def _init_add_args(argp):
    super(__class__,__class__)._init_add_args(argp)
    # Revocation policy
    argp.add_argument('--rev-tidy-factor', action='store',
                      type=float, default=8)
    argp.add_argument('--overhead-factor', action='store',
                      type=float, default=5)
    argp.add_argument('--tidy-factor', action='store',
                      type=int, default=1,
                      help='Suppress revocation if sufficient TIDY')
    argp.add_argument('--revoke-min-time', action='store', type=float, default=0)
    argp.add_argument('--revoke-lru', action='store', type=int, default=0)

    # Placement policy
    argp.add_argument('--best-fit', action='store_const',
                      const=True, default=False)

    # Reuse policy
    argp.add_argument('--unsafe-reuse', action='store_const', const=True,
                      default=False,
                      help='free immediately to reusable state')

  def _init_handle_args(self, args):
    super(__class__,self)._init_handle_args(args)
    self._overhead_factor = args.overhead_factor
    self._tidy_factor     = args.tidy_factor
    self._rev_tidy_factor = args.rev_tidy_factor
    assert args.revoke_min_time >= 0
    self._revoke_t        = args.revoke_min_time * 1E9
    self._rev_lru         = args.revoke_lru

    self._lastrevt = 0  # Time of last revocation pass

    self._bestfit = args.best_fit

    if args.unsafe_reuse :
      self._on_bucket_free = self._on_bucket_free_unsafe

  def _maybe_revoke(self):
    # Revoke only if all of
    #
    # we're above our permitted overhead factor (which is the ratio of BUMP|WAIT to JUNK buckets)
    #
    # we're above our inverse occupancy factor (which is the ratio of BUMP|WAIT to TIDY buckets)
    #
    # It's been more than N seconds since we last revoked
    #
    # Revoking now would grow TIDY by a sufficient quantity

    ts = self._tslam()

    ntidy = self._maxbix - self._njunkb - self._nbwb
    if (     (self._njunkb >= self._overhead_factor * self._nbwb)
         and (self._nbwb >= self._tidy_factor * ntidy)
         and (ts - self._lastrevt >= self._revoke_t)
       ):

        self._predicated_revoke_best(lambda nrev : ntidy < self._rev_tidy_factor * nrev,
                revoke=map(lambda x : x[0], itertools.islice(self._junklru, self._rev_lru)))
        self._lastrevt = self._tslam()

  def _alloc_place_small(self, stk, sz, bbks, tidys) :
    try :
        # If there exists an open BUMP bucket, use that
        return next(bbks)
    except StopIteration :
        # Go claim a block; if bestfit, will be the smallest available
        # block, to help more densely pack small object buckets.
        return self._alloc_place_large(stk, 1, tidys)

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

  def _on_bucket_free_unsafe(self, bix, bsz): return False
