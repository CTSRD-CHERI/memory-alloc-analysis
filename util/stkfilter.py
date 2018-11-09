#!/usr/bin/python3

# Consume a trace and replace the stacks with their identifiers in a
# database.  This, as it turns out, pays dividends later: there are fewer
# bytes being pushed through the parser and because there tend not to be
# that many stacks in the trace, we can precompute behaviors and look them
# up rather than parse and react every time.

import argparse
import logging
import os
import sqlite3
import sys

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(sys.path[0]))

from common.misc import Publisher
from common.run import Run, Unrun

argp = argparse.ArgumentParser(description='Replace stacks with skolems')
argp.add_argument('database', action='store', type=str)
argp.add_argument('--log-level', help="Set the logging level",
                  choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                  default="INFO")
args = argp.parse_args()

logging.basicConfig(level=logging.getLevelName(args.log_level))

con = sqlite3.connect(args.database)

def qm(stk) :
  if stk == "" : return stk
  c = con.execute("""SELECT stkid FROM stacks WHERE stk = ?""", (stk,)).fetchone()
  return c[0] if c is not None else "XXX " + stk

run = Run(sys.stdin)
tslam = lambda : run.timestamp_ns
unrun = Unrun(tslam, out=sys.stdout)

class LineMapper() :
  def allocd  (self, stk, tid, begin, end) : unrun.allocd  (None, qm(stk), tid, begin, end)
  def freed   (self, stk, tid, begin)      : unrun.freed   (None, qm(stk), tid, begin)
  def reallocd(self, stk, tid, bo, bn, en) : unrun.reallocd(None, qm(stk), tid, bo, bn, en)
  def mapd    (self, stk, tid, b, e, prot) : unrun.mapd    (None, qm(stk), tid, b, e, prot)
  def unmapd  (self, stk, tid, b, e)       : unrun.unmapd  (None, qm(stk), tid, b, e)

  def size_measured(self, sz)              : unrun.size_measured(None, sz)
  def sweep_size_measured(self, sz)        : unrun.sweep_size_measured(None, sz)

lm = LineMapper()
run.register_trace_listener(lm)
run.register_addr_space_sample_listener(lm)
run.replay()
con.close()
