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

def draw(output, ltlim, szlim, q) :

  def szf(sz) :
      if sz <= 16 : return sz
      return int(math.log2(sz)*10) - (40-16)

  def ltf(lt) :
      return int(math.log10(lt))

  d = numpy.zeros(shape=(ltf(ltlim)+1,szf(szlim)+1),dtype=numpy.int32)

  for (sz,fts,ats) in q:
      if fts is None :
        # immortal object never freed
        d[ltf(ltlim),szf(sz)] += 1
      else :
        d[ltf(fts-ats),szf(sz)] += 1

  plt.figure(figsize=(szf(szlim)/5,10),dpi=100)
  plt.imshow(d, norm=mplc.PowerNorm(0.3))
  plt.ylabel("Lifetime (log10 nsec)")
  plt.xlabel("Object size bin")
  plt.tight_layout()
  if output is None:
      plt.show()
  else :
      plt.savefig(output,bbox_inches='tight')

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(sys.path[0]))

    argp = argparse.ArgumentParser(description='Generate histogram from allocation trace database')
    argp.add_argument('database', action='store', help="Input database")
    argp.add_argument('max_size', action='store', type=int, help="Maximum allocation size")
    argp.add_argument('--min_size', action='store', type=int, default=0, help="Minimum allocation size")
    argp.add_argument('stklike', action='store', help="Filter allocation stack")
    argp.add_argument('--output', action='store', help="Output file name")
    args = argp.parse_args()
    stklike = args.stklike
    szlim = args.max_size
    szmin = args.min_size
    ltlim = 10**30

    con = sqlite3.connect(args.database)
    q = con.execute("""SELECT sz, fts, ats as lt FROM allocs JOIN stacks ON allocs.stkid = stacks.stkid WHERE stk LIKE ? and sz BETWEEN ? AND ?""", (stklike,szmin,szlim))

    draw(args.output, ltlim, szlim, q)
