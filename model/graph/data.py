#import glob
import sys

fn = sys.argv[1] if len(sys.argv) > 1 else None
with open(fn, 'r') if fn is not None else sys.stdin as f:
    data0 = [[int(s.strip()) for s in line.split('\t')] for line in f if not line.startswith('#')]
data0_label = fn if fn is not None else ''
