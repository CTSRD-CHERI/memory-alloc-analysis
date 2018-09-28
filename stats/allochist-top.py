import argparse
import ast
import itertools
import logging
import os
import re
import sqlite3
import sys

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(sys.path[0]))
    logging.basicConfig(level=logging.INFO)

from stats.allochist import draw as ahdraw

argp = argparse.ArgumentParser(description='Generate histogram from allocation trace database')
argp.add_argument('database', action='store', help="Input database")
argp.add_argument('--stk-pfxre', action='store', type=ast.literal_eval, default=[],
                  help="Filter stack by prefix list of REs"
                 )
argp.add_argument('--just-testing', action='store', type=int, default=0,
                  help="Use a very small subset of allocations to test filters; 2 to disable rendering, too"
                 )
args = argp.parse_args()

alloctable = """allocs"""
if args.just_testing != 0 :
  # For much-accelerated testing: pull a small number of rows from all allocs
  # (but be sure to pick those for which we have stacks)
  alloctable = """(SELECT allocs.*""" \
               """  FROM allocs""" \
               """  JOIN stkmangle ON allocs.stkid == stkmangle.stkid LIMIT 2000)""" \
               """ AS allocs"""

con = sqlite3.connect(args.database)
con.execute("""PRAGMA temp_store = 1 ;""")
con.execute("""PRAGMA temp_store_directory = "/dev/shm" ;""")

sstks = con.execute("""SELECT count(*) FROM stacks ;""").fetchone()[0]
logging.info("Mangling %d stacks...", sstks)
con.execute("""CREATE TEMP TABLE stkmangle (stkid INTEGER PRIMARY KEY, stk TEXT) ;""")
hit = 0
for (stkid, stk) in con.execute("""SELECT stkid, stk FROM stacks ;""") :
  stkwords = stk.split()

  if stkwords == [] : continue

  if not all(map(lambda p : re.match(*p),zip(args.stk_pfxre, stkwords))) : continue
  mangle = stkwords[len(args.stk_pfxre)+1]

  hit += 1
  con.execute("""INSERT INTO stkmangle (stkid, stk) VALUES (?,?)""", (stkid, mangle))
if hit == 0 :
    logging.error("No stacks survived filter; bailing out")
    sys.exit(1)
logging.info("Filter kept %d stacks", hit)
fstr = '-'.join(args.stk_pfxre)

logging.info("Creating filtered allocation table ...")
con.execute("""CREATE TEMP TABLE fallocs AS SELECT allocs.* FROM %s """ \
            """ JOIN stkmangle ON allocs.stkid == stkmangle.stkid """ \
            % (alloctable,))

salloc = con.execute("""SELECT COUNT(*) FROM fallocs """).fetchone()[0]
logging.info("Grouping %d allocs (this may take a long while)...", salloc)
q = con.execute("""SELECT"""
                """ COUNT(*) AS c, stk, min(sz), max(sz)"""
                """ FROM fallocs JOIN stkmangle ON fallocs.stkid == stkmangle.stkid"""
                """ GROUP BY stk ORDER BY c DESC LIMIT 5""")
for (c, stk, mi, ma) in q:
    out = "%s-%s-%s-all.png" % \
            (os.path.splitext(os.path.basename(args.database))[0], fstr, stk)
    logging.info("Generating %s (%d or %2.2f%% of allocs)", out, c, float(c)/salloc * 100.0)

    if args.just_testing < 2 :
      q2 = con.execute("""SELECT sz, fts, ats as lt"""
                       """ FROM fallocs """
                       """ WHERE stkid IN (SELECT stkid FROM stkmangle WHERE stk = ?)"""
                       """  AND sz BETWEEN ? AND ?""",
                       (stk,mi,ma))
      ahdraw(out, 10**30, ma, q2)
