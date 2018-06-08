#import glob
import sys

data0 = [[int(s.strip()) for s in line.split('\t')] for line in sys.stdin if not line.startswith('#')]
data0_label = 'Chromium'
