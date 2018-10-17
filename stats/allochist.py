#!/usr/bin/env python3

import argparse
import itertools
import math
import matplotlib.colors as mplc
import matplotlib.pyplot as plt
import numpy
import os
import sqlite3
import sys

metakq="""SELECT value FROM miscmeta WHERE key = ?"""

def makeszf(minsz, maxsz) :
    # def szf(sz) :
    #     if sz is None : return szf(szlim)
    #     if sz <= 16 : return sz
    #     return int(math.log2(sz)*10) - (40-16)

    def szf(sz) :
        if   sz is None : return 7
        elif sz <=   16 : return 0
        elif sz <=   32 : return 1
        elif sz <=   64 : return 2
        elif sz <=  128 : return 3
        elif sz <=  256 : return 4
        elif sz <=  512 : return 5
        elif sz <= 1024 : return 6
        else            : return 7

    return szf

def draw(output, ltlim, szf, q, et) :

  def ltf(lt) :
      return int(math.log10(lt))

  d = numpy.zeros(shape=(ltf(ltlim)+1,szf(None)+1),dtype=numpy.int32)

  for (sz,fts,ats) in q:
    if fts is None :
      if et is None :
        # immortal object never freed
        d[ltf(ltlim),szf(sz)] += 1
        continue
      else :
        fts = et
    d[ltf(fts-ats),szf(sz)] += 1

  plt.figure(figsize=(szf(None)/5,10),dpi=100)
  plt.imshow(d, norm=mplc.PowerNorm(0.3))
  plt.ylabel("Lifetime (log10 nsec)")
  plt.xlabel("Object size bin")
  plt.tight_layout()
  if output is None:
      plt.show()
  else :
      plt.savefig(output,bbox_inches='tight')

def etsetup(con):
  endtime   = con.execute(metakq, ("lasttime" ,)).fetchone()[0]
  starttime = con.execute(metakq, ("firsttime",)).fetchone()[0]
  return (endtime-starttime, endtime)

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(sys.path[0]))

    argp = argparse.ArgumentParser(description='Generate histogram from allocation trace database')
    argp.add_argument('--min_size', action='store', type=int, default=0, help="Minimum allocation size")
    argp.add_argument('--output', action='store', help="Output file name")
    argp.add_argument('--free-at-exit', action='store_const', const=True, default=False,
                      help="Consider all objects free at end of trace")
    argp.add_argument('database', action='store', help="Input database")
    argp.add_argument('max_size', action='store', type=int, help="Maximum allocation size")
    argp.add_argument('stklike', action='store', help="Filter allocation stack")
    args = argp.parse_args()
    stklike = args.stklike
    szlim = args.max_size
    szmin = args.min_size

    con = sqlite3.connect(args.database)

    (dt, et) = etsetup(con)

    aet = None
    if args.free_at_exit :
        # Add one nanosecond so we never see precisely 0 lifetime, since we love log plots
        aet = et + 1 

    q = con.execute("""SELECT sz, fts, ats as lt FROM allocs JOIN stacks ON allocs.stkid = stacks.stkid WHERE stk LIKE ? and sz BETWEEN ? AND ?""", (stklike,szmin,szlim))

    draw(args.output, dt, mkszf(szmin, szmax), q, aet)
