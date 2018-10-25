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

import stats.allochist as ah

argp = argparse.ArgumentParser(description='Generate histogram from allocation trace database')
argp.add_argument('database', action='store', help="Input database")
argp.add_argument('n', nargs='?', action='store', type=int, default=5)
argp.add_argument('--sizefn', action='store', type=str, default="compact",
                  choices=["compact", "lesscompact", "clingy"],
                  help="Size binning function"
                 )
argp.add_argument('--stk-pfxre', action='store', type=ast.literal_eval, default=[ "" ],
                  help="Filter stack by prefix list of REs"
                 )
argp.add_argument('--free-at-exit', action='store_const', const=True, default=False,
                  help="Consider all objects free at end of trace")
argp.add_argument('--no-stk-filter', action='store_const', const=True, default=False,
                  help="Use whole stacks for partitioning, not filtered values")
argp.add_argument('--just-testing', action='store', type=int, default=0,
                  help="Use a very small subset of allocations to test filters; 2 to disable rendering, too"
                 )
argp.add_argument('--no-log', action='store_const', const=True, default=False,
                  help="Disable generation of log file")
args = argp.parse_args()

dbbn = os.path.splitext(os.path.basename(args.database))[0]

if args.no_stk_filter :
  fstr = 'full'
else :
  fstr = '-'.join(args.stk_pfxre)

logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(levelname)s %(message)s" )
if args.just_testing == 0 and not args.no_log :
    fl = logging.FileHandler("%s-%s.log" % (dbbn, fstr), mode='w')
    fl.setFormatter(logging.Formatter("%(asctime)-15s %(levelname)s %(message)s"))
    fl.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(fl)

alloctable = """allocs"""
if args.just_testing != 0 :
  # For much-accelerated testing: pull a small number of rows from all allocs
  # (but be sure to pick those for which we have stacks)
  if args.no_stk_filter :
    alloctable = """(SELECT allocs.*""" \
                 """  FROM allocs""" \
                 """  LIMIT 2000)""" \
                 """ AS allocs"""
  else :
    alloctable = """(SELECT allocs.*""" \
                 """  FROM allocs""" \
                 """  JOIN stkmangle ON allocs.stkid == stkmangle.stkid LIMIT 2000)""" \
                 """ AS allocs"""

con = sqlite3.connect(args.database)
con.execute("""PRAGMA temp_store = 1 ;""")
con.execute("""PRAGMA temp_store_directory = "/auto/homes/nwf20/scrl/memory-runs" ;""")

(dt, et) = ah.etsetup(con)

# def tick() :
#   logging.debug("SQLite tick...")
# con.set_progress_handler(tick, 100000000)

aet = None
if args.free_at_exit :
  # Add one nanosecond so we never see precisely 0 lifetime, since we love log plots
  aet = et + 1

sstks = con.execute("""SELECT count(*) FROM stacks ;""").fetchone()[0]

if not args.no_stk_filter :
  logging.info("Mangling %d stacks...", sstks)
  con.execute("""CREATE TEMP TABLE stkmangle (stkid INTEGER PRIMARY KEY, stk TEXT) ;""")
  hit = 0
  for (stkid, stk) in con.execute("""SELECT stkid, stk FROM stacks ;""") :
    stkwords = stk.split()

    if stkwords == [] : continue

    if not all(map(lambda p : re.match(*p),zip(args.stk_pfxre, stkwords))) : continue
    mangle = stkwords[len(args.stk_pfxre)]

    hit += 1
    con.execute("""INSERT INTO stkmangle (stkid, stk) VALUES (?,?)""", (stkid, mangle))
  if hit == 0 :
      logging.error("No stacks survived filter; bailing out")
      sys.exit(1)
  logging.info("Filter kept %d stacks", hit)

if not args.no_stk_filter :
  logging.info("Creating filtered allocation table ...")
  con.execute("""CREATE TEMP TABLE fallocs AS SELECT allocs.* FROM %s """ \
              """ JOIN stkmangle ON allocs.stkid == stkmangle.stkid """ \
              % (alloctable,))

  salloc = con.execute("""SELECT COUNT(*) FROM fallocs""").fetchone()[0]
else :
  salloc = con.execute("""SELECT value FROM miscmeta WHERE key = ? """, ("nallocs",)).fetchone()[0]

logging.info("Grouping %d allocs (this may take a long while)...", salloc)
q = con.execute("""SELECT"""
                """ COUNT(*) AS c, {0}, min(sz), max(sz)"""
                """ FROM {1}"""
                """ GROUP BY {0} ORDER BY c DESC LIMIT ?"""
                .format( """ stkid """ if args.no_stk_filter else """ stk """
                  , alloctable if args.no_stk_filter else
                    """ fallocs JOIN stkmangle ON fallocs.stkid == stkmangle.stkid"""
                  )
                , (args.n,))
for (c, stk, mi, ma) in q:
    out = "%s-%s-%s-all.png" % (dbbn, fstr, stk)
    logging.info("Generating %s (%d or %2.2f%% of allocs)", out, c, float(c)/salloc * 100.0)

    if args.just_testing < 2 :
      q2 = con.execute("""SELECT sz, fts, ats as lt"""
                       """ FROM {0} """
                       """ WHERE {1} """
                       """  AND sz BETWEEN ?2 AND ?3"""
                       .format( alloctable if args.no_stk_filter else """ fallocs """
                              , """ stkid == ?1 """ if args.no_stk_filter else
                                """ stkid IN (SELECT stkid FROM stkmangle WHERE stk = ?) """
                              ),
                       (stk,mi,ma))
      ah.draw(out, dt, ah.makeszf(mi,ma,flavor=args.sizefn), q2, aet,
                title=("%s %s %s (%d)" % (dbbn, fstr, stk, c)))
