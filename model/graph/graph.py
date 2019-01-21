#!/usr/bin/env python3
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import math
from data import *

import sys

data0 = np.array(data0)
data0 = np.rot90(np.fliplr(data0))
x = 0
y1, y2, y3, y4, y5, y6, y7 = 1, 2, 3, 4, 5, 6, 7

data0[x] -= data0[x][0]    # offset time from the start
time_s = data0[x] / 10**9 # time ns to s

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


def prefix_units(values, prefix_radix:str):
    assert prefix_radix in ('decimal', 'binary')

    base = 10 if prefix_radix == 'decimal' else 2
    magnitudes = tuple(range(0, 18 + 1, 3)) if prefix_radix == 'decimal' else\
                 tuple(range(0, 60 + 1, 10))
    prefixes = ('', 'K', 'M', 'G', 'T', 'P', 'E') if prefix_radix == 'decimal' else\
               ('', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei')
    denominators = [base**mag for mag in magnitudes]
    prefix_to_denominator = dict(zip(prefixes, denominators))

    # Lower first threshold from 1 to 0 to weigh in fractional values.
    # Note that null values are excluded as they may have any prefix.
    thresholds = list(denominators)
    thresholds[0] = 0
    threshold_to_prefix = dict(zip(thresholds, prefixes))
    vals_for_histogram = [v for v in values if v > 0]

    freqs, edges = np.histogram(vals_for_histogram, bins=thresholds)
    # most common threshold
    mct = max(zip(freqs, edges), key=(lambda fe_pair: fe_pair[0]))[1]
    prefix = threshold_to_prefix[mct]
    denominator = prefix_to_denominator[prefix]
    #print("Most common threshold: ", mct)
    #print("Most common prefix: ", threshold_to_prefix[mct])

    return prefix, denominator

def readable_float(x):
    assert x >= 0, x
    frac, integ = math.modf(x)
    if integ >= 100:
        return '{0:.0f}'.format(x)
    if integ >= 1:
        return '{0:.1f}'.format(x)
    return '{0:.2f}'.format(x)


matplotlib.rc('font', size=11)
#fig, ax = plt.subplots()
plt.subplot(4, 1, 1)
plt.subplots_adjust(hspace=1)

aspace_total_prefix, aspace_total_denominator = prefix_units(data0[y1], 'binary')
aspace_total = data0[y1] / aspace_total_denominator        # aspace-total
aspace_sweep = data0[y2] / aspace_total_denominator        # aspace-sweep
aspace_allocator = data0[y3] / aspace_total_denominator    # aspace-allocator
allocator_allocd = data0[y4] / aspace_total_denominator    # allocd
plt.plot(time_s, aspace_total, time_s, aspace_sweep, time_s, aspace_allocator,
         time_s, allocator_allocd)
plt.title('Address space usage over time\n(data-set "{0}")'.format(data0_label))
plt.legend(['Aspace total', 'Aspace to sweep', 'Aspace of allocator', 'Allocd by allocator'],
           loc='lower right', bbox_to_anchor=[1, 1])
plt.xlabel('Time (s)')
plt.ylabel('Amount ({0}B)'.format(aspace_total_prefix))

plt.subplot(4, 1, 2)
sweep_1s, time_ns_windows = cum_time_window(data0[y6], data0[x], 10**9)
time_s_windows = np.array([1 if tw < 10**9 else tw / 10**9 for tw in time_ns_windows])
sweep_per_s = sweep_1s / time_s_windows
sweep_per_s_prefix, sweep_per_s_denominator = prefix_units(sweep_per_s, 'binary')
sweep_per_s /= sweep_per_s_denominator
#print(sweep_per_s)
plt.plot(time_s, sweep_per_s, color='blue')
plt.title('Sweeping amount requirement over time\nmax={0}{2}B/s   avg={1}{2}B/s'
          .format(readable_float(max(sweep_per_s)),
                  readable_float(np.average(sweep_per_s)), sweep_per_s_prefix))
plt.xlabel('Time (s)')
plt.ylabel('Amount ({0}B/s)'.format(sweep_per_s_prefix))

plt.subplot(4, 1, 3)
sweeps_1s, _ = cum_time_window(data0[y5], data0[x], 10**9)
sweeps_per_s = sweeps_1s / time_s_windows
sweeps_per_s_prefix, sweeps_per_s_denominator = prefix_units(sweeps_per_s, 'decimal')
sweeps_per_s /= sweeps_per_s_denominator
plt.plot(time_s, sweeps_per_s, color='red')
plt.title('Sweeps required over time\nmax={0}{2}/s   avg={1}{2}/s'
          .format(readable_float(max(sweeps_per_s)),
                  readable_float(np.average(sweeps_per_s)), sweeps_per_s_prefix))
plt.xlabel('Time (s)')
plt.ylabel('Sweeps {0}'.format(('('+sweeps_per_s_prefix+')') if sweeps_per_s_prefix else ''), color='red')

plt.subplot(4, 1, 4)
sweeps_ivals_1s, _ = cum_time_window(data0[y7], data0[x], 10**9)
sweeps_ivals_per_s = sweeps_ivals_1s / time_s_windows
sweeps_ivals_per_s_prefix, sweeps_ivals_per_s_denominator = prefix_units(sweeps_ivals_per_s, 'decimal')
sweeps_ivals_per_s /= sweeps_ivals_per_s_denominator
plt.plot(time_s, sweeps_ivals_per_s, color='blue')
plt.title('Sweep intervals required over time\nmax={0}{2}/s   avg={1}{2}/s'
          .format(readable_float(max(sweeps_ivals_per_s)),
                  readable_float(np.average(sweeps_ivals_per_s)), sweeps_ivals_per_s_prefix))
plt.xlabel('Time (s)')
plt.ylabel('Amount {0}'.format(('('+sweeps_ivals_per_s_prefix+')') if sweeps_ivals_per_s_prefix else ''), color='blue')
plt.savefig('{0}-aspace_stats.eps'.format(data0_label.lower()))

plt.show()
