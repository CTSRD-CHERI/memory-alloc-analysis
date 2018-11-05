import argparse
import ast
import functools
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
argp.add_argument('n', nargs='?', action='store', type=int, default=5,
                  help='Top n to consider')
argp.add_argument('--sizefn', action='store', type=str, default="compact",
                  choices=["compact", "lesscompact", "clingy"],
                  help="Size binning function"
                 )
argp.add_argument('--load-mangle-table', action='store', type=str, default=None,
                  help='Load, do not compute, the stack mangle table')
argp.add_argument('--stk-pfxre', action='store', type=ast.literal_eval, default=[ "" ],
                  help="Filter stack by prefix list of REs"
                 )
argp.add_argument('--no-stk-filter', action='store_const', const=True, default=False,
                  help="Use whole stacks for partitioning, not filtered values")
argp.add_argument('--stk-xor', action='store', type=int, default=None,
                  help="Compress stacks by xor and shift")
#argp.add_argument('--stk-xor-rotate', action='store_true', default=False,
#                  help="Rotate, not shift, in xor stack compression")
argp.add_argument('--stk-xor-mask', action='store', type=int, default=None,
                  help="Mask stacks after xor-and-shift compression")
argp.add_argument('--xlen', action='store', type=int, default=32, choices=[32,64],
                  help="Machine register bit width")
argp.add_argument('--free-at-exit', action='store_const', const=True, default=False,
                  help="Consider all objects free at end of trace")
argp.add_argument('--just-testing', action='store', type=int, default=0,
                  help="Use a very small subset of allocations to test filters; 2 to disable rendering, too"
                 )
argp.add_argument('--no-log', action='store_const', const=True, default=False,
                  help="Disable generation of log file")
argp.add_argument('--save-mangle-table', action='store', type=str, default=None,
                  help="Save the mangled stack table to a file")
args = argp.parse_args()

dbbn = os.path.splitext(os.path.basename(args.database))[0]

if args.stk_xor is None :
  if args.stk_xor_mask is not None :
    print("xor-mask without xor does not make sense", file=sys.stderr)
    os.exit(1)
  # if args.stk_xor_rotate != False :
  #   print("xor-rotate without xor does not make sense", file=sys.stderr)
  #   os.exit(1)
else :
  if args.stk_xor_mask is None :
    args.stk_xor_mask = 2**args.xlen - 1

if args.no_stk_filter :
  fstr = 'full'
elif args.load_mangle_table :
  fstr = os.path.basename(args.load_mangle_table)
else :
  fstr = '-'.join(args.stk_pfxre)

if args.stk_xor is not None :
  fstr += 'xor' + str(args.stk_xor)

logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(levelname)s %(message)s" )
if args.just_testing == 0 and not args.no_log :
    fl = logging.FileHandler("%s-%s.log" % (dbbn, fstr), mode='w')
    fl.setFormatter(logging.Formatter("%(asctime)-15s %(levelname)s %(message)s"))
    fl.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(fl)

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

if args.stk_xor is not None :
  # if args.stk_xor_rotate :
  #   if args.stk_xor >= 0 :
  #     xs = lambda v,s : (v ^ (s << args.stk_xor)) & (args.stk_xor_mask)
  # else :
    if args.stk_xor >= 0 :
      xs = lambda v,s : (v ^ (s << args.stk_xor)) & (args.stk_xor_mask)
    else :
      args.stk_xor = -args.stk_xor
      xs = lambda v,s : (v ^ (s >> args.stk_xor)) & (args.stk_xor_mask)


if not args.no_stk_filter and args.load_mangle_table is None :
  logging.info("Mangling %d stacks...", sstks)
  con.execute("""CREATE TEMP TABLE stkmangle (stkid INTEGER PRIMARY KEY, stk TEXT) ;""")
  hit = 0
  for (stkid, stk) in con.execute("""SELECT stkid, stk FROM stacks ;""") :
    stkwords = stk.split()

    if stkwords == [] : continue

    if not all(map(lambda p : re.match(*p),zip(args.stk_pfxre, stkwords))) : continue

    if args.stk_xor is not None :
      mangle = hex(functools.reduce(xs, map(lambda a : int(a,0), stkwords[::-1]), 0))
    else :
      mangle = stkwords[len(args.stk_pfxre)]

    hit += 1
    con.execute("""INSERT INTO stkmangle (stkid, stk) VALUES (?,?)""", (stkid, mangle))
  if hit == 0 :
      logging.error("No stacks survived filter; bailing out")
      sys.exit(1)
  logging.info("Filter kept %d stacks", hit)
elif not args.no_stk_filter and args.load_mangle_table is not None :
  logging.info("Loading mangle table from file '%s'", args.load_mangle_table)
  con.execute("""CREATE TEMP TABLE stkmangle (stkid INTEGER PRIMARY KEY, stk TEXT) ;""")

  import csv
  hit = 0
  with open(args.load_mangle_table, 'r', newline='') as fi:
    for row in csv.reader(fi,quoting=csv.QUOTE_NONNUMERIC) :
      con.execute("""INSERT INTO stkmangle (stkid, stk) VALUES (?,?)""", row)
      hit += 1

  logging.info("Loaded mangle table with %d stacks", hit)
elif args.no_stk_filter and args.load_mangle_table is not None :
  logging.error("Mixing no-stack-filter and load-mangle-table?")
  os.exit(1)
else : # no stack filter and no loaded table
  con.execute("""CREATE TEMP VIEW stkmangle AS SELECT * FROM stacks;""")

if not args.no_stk_filter :
  if args.save_mangle_table :
    logging.info("Storing mangle table to file '%s'", args.save_mangle_table)

    import csv
    with open(args.save_mangle_table, 'w') as fo:
      w = csv.writer(fo, quoting=csv.QUOTE_NONNUMERIC)
      for row in con.execute("""SELECT stkid, stk FROM stkmangle""") :
        w.writerow(row)

if args.no_stk_filter or hit == sstks:
  logging.info("All stacks survived; not filtering allocation table!")
  con.execute("""CREATE TEMP VIEW fallocs AS SELECT allocs.*, stkmangle.stk FROM allocs """ \
              """ JOIN stkmangle ON allocs.stkid == stkmangle.stkid """ \
              """ LIMIT %d ;""" % ((-1 if args.just_testing == 0 else 2000),))
  if args.just_testing == 0 :
    salloc = con.execute("""SELECT value FROM miscmeta WHERE key = ? """, ("nallocs",)).fetchone()[0]
  else :
    salloc = con.execute("""SELECT COUNT(*) FROM fallocs""").fetchone()[0]
else :
  logging.info("Creating filtered allocation table ...")
  con.execute("""CREATE TEMP TABLE fallocs AS SELECT allocs.*, stkmangle.stk FROM allocs """ \
              """ JOIN stkmangle ON allocs.stkid == stkmangle.stkid """ \
              """ LIMIT ? """,
              ((-1 if args.just_testing == 0 else 2000),))

  salloc = con.execute("""SELECT COUNT(*) FROM fallocs""").fetchone()[0]

logging.info("Grouping %d allocs (this may take a long while)...", salloc)
q = con.execute("""SELECT"""
                """ COUNT(*) AS c, stk, min(sz), max(sz)"""
                """ FROM fallocs """
                """ GROUP BY stk ORDER BY c DESC LIMIT ?"""
                , (args.n,))
for (c, stk, mi, ma) in q:
    out = "%s-%s-%s-all.png" % (dbbn, fstr, stk)
    logging.info("Generating %s (%d or %2.2f%% of allocs)", out, c, float(c)/salloc * 100.0)

    if args.just_testing < 2 :
      q2 = con.execute("""SELECT sz, fts, ats """
                       """ FROM fallocs """
                       """ WHERE fallocs.stkid IN (SELECT stkid FROM stkmangle WHERE stk = ?1) """
                       """  AND sz BETWEEN ?2 AND ?3 """,
                       (stk,mi,ma))
      ah.draw(out, dt, ah.makeszf(mi,ma,flavor=args.sizefn), q2, aet,
                title=("%s %s %s (%d)" % (dbbn, fstr, stk, c)))
