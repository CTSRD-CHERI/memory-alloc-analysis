#!/usr/bin/python3
#
# This script consumes a trace on stdin and writes, for each allocated
# object, a row to the 'allocs' table containing the allocated size, call
# stack, and {alloc,realloc,free} timestamps.  For each reallocation event,
# a similar row is inserted into the 'reallocs' table.
#
# For a reallocated object, the row in the 'allocs' table uses its free
# timestamp for when the object itself, through all of its reallocations, is
# freed.  The 'reallocs' table uses its free timestamp column to indicate
# either ultimate free or another reallocation.  In the former case, the
# realloc.fts equals the alloc.fts for this object.

import argparse
import logging
import os
import sqlite3
import sys

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(sys.path[0]))

from common.run import Run

kviq = "INSERT INTO miscmeta (key,value) VALUES (?,?)"

class MetadataTracker() :
    def __init__(self, tslam, ia, ir) :
        self._sfree   = 0
        self._nextoid = 1
        self._tva2oid = {}  # OIDs
        self._oid2amd = {}  # Allocation metadata (stack, timestamp, size)
        self._oid2irt = {}  # Initial Reallocation Timestamp & sftf
        self._oid2rmd = {}  # most recent Reallocation metadata (stk, ts, osz, nsz)
        self._tslam   = tslam
        self._ia      = ia  # Insert Allocation   (on free)
        self._ir      = ir  # Insert Reallocation (on free or realloc)

    def _allocd(self, stk, tva, sz, now):
        oid = self._nextoid
        self._nextoid += 1
        self._tva2oid[tva] = oid
        self._oid2amd[oid] = [stk, now, sz]

        return oid

    def allocd(self, stk, begin, end) :
        now = self._tslam()

        if self._tva2oid.get(begin, None) is not None:
            # synthesize free so we don't lose the object; its lifetime
            # will be a little longer than it should be...
            logging.warn("malloc inserting free for tva=%x at ts=%d", begin, now)
            self.freed("", begin)

        oid = self._allocd(stk, begin, end-begin, now)
        self._oid2rmd[oid]   = None

    def freed(self, _, begin) :
        now = self._tslam()

        oid = self._tva2oid.pop(begin, None)
        if oid is None :
            if begin != 0 :
                # Warn, but do not insert anything into the database
                logging.warn("Free of non-allocated object; tva=%x ts=%d",
                             begin, now)
            return

        amd = self._oid2amd.pop(oid)
        irt = self._oid2irt.pop(oid, (None, self._sfree))
        self._ia(oid, amd, irt, now)

        rmd = self._oid2rmd.pop(oid, None)
        if rmd is not None:
            self._ir(oid, rmd, now, self._sfree)
            # Free most recently reallocated size
            self._sfree += rmd[3]
        else :
            # Free original size
            self._sfree += amd[2]

    def reallocd(self, stk, otva, ntva, etva) :
        now = self._tslam()
        nsz = etva - ntva

        if ntva != otva and self._tva2oid.get(ntva, None) is not None :
            # Synthesize a free before we clobber something
            logging.warn("realloc inserting free for tva=%x at ts=%d", ntva, now)
            self.freed("", ntva)

        oid = self._tva2oid.pop(otva, None)
        if oid is None :
            # allocation via realloc or damaged trace
            oid = self._allocd(stk, ntva, nsz, now)
            self._oid2rmd[oid] = (stk, now, 0, nsz)
        elif etva == ntva :
            # free via realloc
            self.freed(None, otva)
        else :
            rmd = self._oid2rmd.pop(oid, None)
            osz = None
            if rmd is not None :
                self._ir(oid, rmd, now, self._sfree)
                osz = rmd[3]
            else :
                osz = self._oid2amd[oid][2]
                self._oid2irt[oid] = (now, self._sfree)
            self._oid2rmd[oid] = (stk, now, osz, nsz)
            self._tva2oid[ntva] = oid
            self._sfree += osz

    def finish(self) :
      # Can't just iterate the keys, because free deletes.  So just repeatedly
      # restart a fresh iterator.
      while self._tva2oid != {} :
        k = next(iter(self._tva2oid.keys()))
        self.freed("", k)

if __name__ == "__main__" and __package__ is None:

  argp = argparse.ArgumentParser(description='Generate a database of allocation metadata')
  argp.add_argument('database', action='store', help="Output database")
  argp.add_argument("--log-level", help="Set the logging level",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    default="INFO")
  args = argp.parse_args()

  logging.basicConfig(level=logging.getLevelName(args.log_level))

  if os.path.isfile(args.database) :
    print("Refusing to clobber existing file", file=sys.stderr)
    sys.exit(-1)

  con = sqlite3.connect(args.database)
  con.execute("CREATE TABLE stacks "
              "(stkid INTEGER PRIMARY KEY NOT NULL"
              ", stk TEXT UNIQUE NOT NULL)")
  con.execute("CREATE TABLE allocs "
              "(oid INTEGER PRIMARY KEY NOT NULL" # Object ID
              ", sz INTEGER NOT NULL"             # SiZe
              ", stkid TEXT NOT NULL"             # STacK
              ", ats INTEGER NOT NULL"            # Allocation Time Stamp
              ", rts INTEGER"                     # Reallocation Time Stamp
              ", fts INTEGER"                     # Free Time Stamp
              ", sftf INTEGER NOT NULL"           # Sum Free at Time of Free/Realloc
              ", FOREIGN KEY(stkid) REFERENCES stacks(stkid)"
              ")")
  con.execute("CREATE TABLE reallocs "
              "(oid INTEGER NOT NULL"             # Object ID
              ", osz INTEGER NOT NULL"            # Old SiZe
              ", nsz INTEGER NOT NULL"            # New SiZe
              ", stkid INTEGER NOT NULL"          # STacK
              ", ats INTEGER NOT NULL"            # Allocaton Time Stamp
              ", fts INTEGER"                     # Free Time Stamp
              ", sftf INTEGER NOT NULL"           # Sum Free at Time of Free
              ", FOREIGN KEY(stkid) REFERENCES stacks(stkid)"
              ")")
  con.execute("CREATE TABLE miscmeta "
              "(key TEXT UNIQUE NOT NULL"
              ", value NOT NULL"
              ")")

  def istk(stk) :
    con.execute("INSERT OR IGNORE INTO stacks (stk) VALUES (?)", (stk,))
    q = con.execute("SELECT stkid FROM stacks WHERE stk = ?", (stk,))
    for (stkid,) in q : return stkid

  na = 0
  def ia(oid, amd, irtf, fts) :
    global na
    (astk, ats, asz) = amd
    (irt, sftf) = irtf
    stkid = istk(astk)
    con.execute("INSERT INTO allocs "
                "(oid,sz,stkid,ats,rts,fts,sftf) VALUES (?,?,?,?,?,?,?)",
                (oid,asz,stkid,ats,irt,fts,sftf)
    )
    na += 1

  nr = 0
  def ir(oid, rmd, fts, sftf) :
    global nr
    (rstk, rts, rosz, rnsz) = rmd
    stkid = istk(rstk)
    con.execute("INSERT INTO reallocs "
                "(oid,osz,nsz,stkid,ats,fts,sftf) VALUES (?,?,?,?,?,?,?)",
                (oid,rosz,rnsz,stkid,rts,fts,sftf)
    )
    nr += 1

  run = Run(sys.stdin)
  tslam = lambda : run.timestamp_ns
  at = MetadataTracker(tslam, ia, ir)
  run._trace_listeners += [ at ]
  run.replay()

  con.execute(kviq, ("firsttime", run.timestamp_initial_ns))
  con.execute(kviq, ("lasttime", run.timestamp_ns))

  at._tslam = lambda : None
  at.finish()

  con.execute(kviq, ("nallocs", na))
  con.execute(kviq, ("nreallocs", nr))

  con.commit()
  con.close()

  print("Aggregate statistics", file=sys.stderr)
  print("  %d allocations" % na, file=sys.stderr)
  print("  %d reallocs" % nr, file=sys.stderr)
