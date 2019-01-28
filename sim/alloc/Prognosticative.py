# A maximally informed allocator, that knows, with certainty, the right
# place to put an object so that there is one ever-growing WAIT span at the
# bottom of the address space.  This is not useful per se, since its
# knowledge is impossibly oracular, but it may still provide useful insights
# in visualizations.  It's also a relatively interesting test of various
# pieces of machinery, including the trace-to-db tool and the
# TraditionalAllocatorBase (unlike most allocator simulations we have so
# far, it really rains objects all over the addres space and so stresses the
# heap models in new ways).

import logging
import sqlite3

from sim.TraditionalAllocatorBase import TraditionalAllocatorBase

class Allocator(TraditionalAllocatorBase):

  __slots__ = (
    '_eva2oid',
    '_oid',
    '_tdb'
  )

  @staticmethod
  def _init_add_args(argp):
    super(__class__,__class__)._init_add_args(argp)

    argp.add_argument('database', action='store', type=str)

  def _init_handle_args(self, args):
    super(__class__,self)._init_handle_args(args)

    self._tdb = sqlite3.connect(args.database)

    self._eva2oid = {}
    self._oid = 0

  def _alloc_place(self, _stk, _sz) :
    self._oid += 1

    if __debug__ : logging.debug(">_alloc_place: oid=%d", self._oid)

    row = self._tdb.execute("SELECT sz, sftf FROM allocs WHERE oid = ?", (self._oid, )) \
              .fetchone()

    # Verify the allocation size matches the database
    assert row[0] == _sz, "Database corruption?"

    # Extract placement from database, which accumulates sftf from 0, and add base
    pos = row[1] + self._evp2eva(self._basepg)

    if __debug__ : logging.debug("<_alloc_place: oid=%d pos=%x", self._oid, pos)

    self._eva2oid[pos] = self._oid

    return pos

  def _free(self, event, eva):
    del self._eva2oid[eva]
    super(__class__,self)._free(event, eva)

  # This is kind of gross; we reach all the way back into
  # RenamingAllocatorBase to handle this one ourselves.
  def reallocd(self, event, otva, ntva, etva) :
    oeva = self._tva2eva.get(otva, None)
    if oeva is None :
        if __debug__ : logging.debug("=reallocd is alloc at ts=%d", self._tslam())
        self.allocd(event, ntva, etva)
    elif etva == ntva :
        if __debug__ : logging.debug("=reallocd is free at ts=%d", self._tslam())
        self.freed(event, otva)
    else :
        sz = etva - ntva
        oid = self._eva2oid[oeva]
        now = self._tslam()

        if __debug__ : logging.debug(">reallocd oid=%d ts=%d", oid, now)

        row = self._tdb.execute("SELECT osz, nsz, sftf FROM reallocs WHERE oid = ? AND ats = ?",
                        (oid, now)) \
                  .fetchone()

        # Verify sizes in database
        assert row[0] == self._eva2sz[self._tva2eva[otva]]
        assert row[1] == sz

        # Extract placement from database, which accumulates sftf from 0, and add base
        pos = row[2] + self._evp2eva(self._basepg)
        
        self._mark_allocated(pos, sz)
        self._ensure_mapped(event, pos, sz)
        self._eva2sz[pos] = sz
        self._tva2eva[ntva] = pos
        self._eva2oid[pos] = oid

        self._free(event, oeva)

        self._publish('reallocd', event, oeva, pos, pos+sz)
