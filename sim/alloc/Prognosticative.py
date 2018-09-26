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

    pos = self._tdb.execute("SELECT sftf FROM allocs WHERE oid = ?", (self._oid, )) \
              .fetchone()[0]

    if __debug__ : logging.debug("<_alloc_place: oid=%d pos=%x", self._oid, pos)

    self._eva2oid[pos] = self._oid

    return pos

  def _free(self, stk, eva):
    del self._eva2oid[eva]
    super(__class__,self)._free(stk, eva)

  # This is kind of gross; we reach all the way back into
  # RenamingAllocatorBase to handle this one ourselves.
  def reallocd(self, stk, otva, ntva, etva) :
    oeva = self._tva2eva.get(otva, None)
    if oeva is None :
        if __debug__ : logging.debug("=reallocd is alloc at ts=%d", self._tslam())
        self.allocd(stk, ntva, etva)
    elif etva == ntva :
        if __debug__ : logging.debug("=reallocd is free at ts=%d", self._tslam())
        self.freed(stk, otva)
    else :
        sz = etva - ntva
        oid = self._eva2oid[oeva]
        now = self._tslam()

        if __debug__ : logging.debug(">reallocd oid=%d ts=%d", oid, now)

        pos = self._tdb.execute("SELECT sftf FROM reallocs WHERE oid = ? AND ats = ?",
                        (oid, now)) \
                  .fetchone()[0]
        
        self._mark_allocated(pos, sz)
        self._ensure_mapped(stk, pos, sz)
        self._eva2sz[pos] = sz
        self._tva2eva[ntva] = pos
        self._eva2oid[pos] = oid

        self._free(stk, oeva)

        self._publish('reallocd', stk, oeva, pos, pos+sz)
