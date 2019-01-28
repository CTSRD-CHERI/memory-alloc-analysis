import itertools
from sim.TraditionalAllocatorBase import TraditionalAllocatorBase

class Allocator(TraditionalAllocatorBase):
  pass

  def _maybe_revoke(self, event):
    # XXX configurable policy
    if self._njunk >= self._nwait and len(self._junklru) >= 16 :
      self._do_revoke_best_and(event, revoke=[loc for (loc, _) in itertools.islice(self._junklru,8)])

