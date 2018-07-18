#!/usr/bin/env python3
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from data import *

import sys

data0 = np.array(data0)
data0 = np.rot90(np.fliplr(data0))
x = 0
y1, y2, y3, y4, y5 = 1, 2, 3, 4, 5

data0[x] -= data0[x][0]    # offset time from the start
time_s = data0[x] / 10**9 # time ns to s

data0[y1] //= 2**20        # aspace-total b to mb
data0[y2] //= 2**20        # aspace-sweep b to mb
data0[y3] //= 2**20        # aspace-allocator b to mb
data0[y4] //= 2**20        # allocd b to mb
data0[y5] //= 2**30        # swept b to gb

#print(data0)

matplotlib.rc('font', size=11)
fig, ax = plt.subplots()
plt.plot(time_s, data0[y1], time_s, data0[y2], time_s, data0[y3], time_s, data0[y4])
plt.title('{0} allocator address space usage over time'.format(data0_label))
plt.legend(['Aspace total', 'Aspace to sweep', 'Aspace of allocator', 'Allocd by allocator'])
plt.xlabel('Time (s)')
plt.ylabel('Amount (mb)')
plt.savefig('{0}-aspace_stats-vs-time.eps'.format(data0_label.lower()))

sys.exit()
#sweep_per_ns = (data0[y4][1:] - data0[y4][:-1]) / (data0[x][1:] - data0[x][:-1])
#sweep_per_s = sweep_per_ns * 10**9
##print(sweep_per_s)
#plt.gcf().clear()
#plt.plot(time_s[:-1], sweep_per_s)
#plt.title('{0} allocator sweeping requirement over time'.format(data0_label))
#plt.legend([''])
#plt.xlabel('Time (s)')
#plt.ylabel('Amount (mb/s)')
#plt.savefig('{0}-sweep_per_s-vs-time.eps'.format(data0_label.lower()))
