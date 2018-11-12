#!/usr/bin/env python3
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from data import *

import sys

data0 = np.array(data0)
data0 = np.rot90(np.fliplr(data0))
x = 0
y1, y2, y3, y4, y5, y6, y7 = 1, 2, 3, 4, 5, 6, 7

data0[x] -= data0[x][0]    # offset time from the start
time_s = data0[x] / 10**9 # time ns to s

data0[y1] //= 2**20        # aspace-total b to mb
data0[y2] //= 2**20        # aspace-sweep b to mb
data0[y3] //= 2**20        # aspace-allocator b to mb
data0[y4] //= 2**20        # allocd b to mb

data0[y5] //= 1000         # sweeps units to thousands
data0[y6] //= 2**30        # swept b to gb
data0[y7] //= 1000         # sweep ivals units to thousands

#print(data0)

def cum_time_window(vals, time, win_size):
    vals_ret = []
    time_ret = []
    win_start_i = 0
    for t, v in zip(time, vals):
        if t - time[win_start_i + 1] > win_size:
            win_start_i += 1
        vals_ret.append(v - vals[win_start_i])
        time_ret.append(t - time[win_start_i])
    return np.array(vals_ret), np.array(time_ret)

matplotlib.rc('font', size=11)
#fig, ax = plt.subplots()
plt.subplot(4, 1, 1)
plt.subplots_adjust(hspace=1)

plt.plot(time_s, data0[y1], time_s, data0[y2], time_s, data0[y3], time_s, data0[y4])
plt.title('Address space usage over time\n(data-set "{0}")'.format(data0_label))
plt.legend(['Aspace total', 'Aspace to sweep', 'Aspace of allocator', 'Allocd by allocator'],
           loc='lower right', bbox_to_anchor=[1, 1])
plt.xlabel('Time (s)')
plt.ylabel('Amount (mb)')

plt.subplot(4, 1, 2)
sweep_1s, time_ns_windows = cum_time_window(data0[y6], data0[x], 10**9)
time_s_windows = np.array([1 if tw < 10**9 else tw / 10**9 for tw in time_ns_windows])
sweep_per_s = sweep_1s / time_s_windows
#print(sweep_per_s)
plt.plot(time_s, sweep_per_s, color='blue')
plt.title('Sweeping amount requirement over time\nmax={0}gb/s   avg={1}gb/s'
          .format(int(max(sweep_per_s)), int(np.average(sweep_per_s))))
plt.xlabel('Time (s)')
plt.ylabel('Amount (gb/s)')

plt.subplot(4, 1, 3)
sweeps_1s, _ = cum_time_window(data0[y5], data0[x], 10**9)
sweeps_per_s = sweeps_1s / time_s_windows
plt.plot(time_s, sweeps_per_s, color='red')
plt.title('Sweeps required over time\nmax={0}k/s   avg={1}k/s'
          .format(int(max(sweeps_per_s)), int(np.average(sweeps_per_s))))
plt.xlabel('Time (s)')
plt.ylabel('Amount (thousands)', color='red')

plt.subplot(4, 1, 4)
sweeps_ivals_1s, _ = cum_time_window(data0[y7], data0[x], 10**9)
sweeps_ivals_per_s = sweeps_ivals_1s / time_s_windows
plt.plot(time_s, sweeps_ivals_per_s, color='blue')
plt.title('Sweep intervals required over time\nmax={0}k/s   avg={1}k/s'
          .format(int(max(sweeps_ivals_per_s)), int(np.average(sweeps_ivals_per_s))))
plt.xlabel('Time (s)')
plt.ylabel('Amount (thousands)', color='blue')
plt.savefig('{0}-aspace_stats.eps'.format(data0_label.lower()))

plt.show()
