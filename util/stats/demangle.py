import argparse
import csv
import os
import sqlite3
import sys

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(sys.path[0]))

argp = argparse.ArgumentParser(description='Demangle stacks from allochist-top')
argp.add_argument('database', action='store', help="Input database")
argp.add_argument('mangle_csv', action='store', help="Saved mangle table")
args = argp.parse_args()

con = sqlite3.connect(args.database)
con.execute("""PRAGMA temp_store = 1 ;""")
con.execute("""PRAGMA temp_store_directory = "%s" ;""" % os.environ.get("TEMPDIR","/tmp"))

con.execute("""CREATE TEMP TABLE stkmangle (stkid INTEGER PRIMARY KEY, stk TEXT) ;""")
with open(args.mangle_csv, 'r', newline='') as fi:
  for row in csv.reader(fi,quoting=csv.QUOTE_NONNUMERIC) :
    con.execute("""INSERT INTO stkmangle (stkid, stk) VALUES (?,?)""", row)

last_stk = None
mangleds = []
for (stk,stkid) in con.execute("""SELECT stk,stkid FROM stkmangle ORDER BY stk""") :
  if stk != last_stk :
    if last_stk is not None :
      print(stk, "%d preimages:" % len(mangleds))
      for m in mangleds : print("", m)
    last_stk = stk
    mangleds = []
  mangleds += [con.execute("""SELECT stk FROM stacks WHERE stkid = ?""", (stkid,)).fetchone()[0]]
