#!/usr/bin/env python3
# Copyright (c) 2018  Lucian Paul-Trifu
# All rights reserved.
# 
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
# ("CTSRD"), as part of the DARPA CRASH research programme.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from collections import namedtuple
from enum import Enum, unique
import sys
import numpy

# https://pypi.org/project/bintrees
from intervaltree import Interval, IntervalTree
from intervalmap import IntervalMap


@unique
class AddrIntervalState(Enum):
    ALLOCD  = 1
    FREED   = 2
    REVOKED = 3

    MAPD    = 4
    UNMAPD  = 5

    __repr__ = Enum.__str__


class AddrInterval(Interval):
    __slots__ = ()

    def __new__(cls, begin, end, state):
        return super().__new__(cls, begin, end, state)

    @property
    def state(self):
        return self.data
    # Required for compatibility with the IntervalMap  
    @property
    def value(self):
        return self.state

    def __repr__(self):
        r = super().__repr__()
        r = r.replace('Interval', __class__.__name__, 1)
        r = r.replace(str(self.begin), hex(self.begin)[2:])
        r = r.replace(str(self.end), hex(self.end)[2:])
        return r

    __str__ = __repr__


def intervaltree_query_checked(tree, point):
    ival = tree[point]
    assert len(ival) <= 1, 'Bug: overlapping address intervals at {0:x} {1}'.format(point, tree)
    return ival.pop() if ival else None


def intervaltree_query_coalesced(tree, point, **kwds):
    ival = intervaltree_query_checked(tree, point)
    if not ival:
        return None
    data_coalesced = {ival.data, }
    data_coalesced.update(kwds.get('coalesce_with', set()))

    ival_left = ival
    while ival_left and ival_left.data in data_coalesced:
        begin = ival_left.begin
        ival_left = intervaltree_query_checked(tree, begin - 1)

    ival_right = ival
    while ival_right and ival_right.data in data_coalesced:
        end = ival_right.end
        ival_right = intervaltree_query_checked(tree, end)

    return AddrInterval(begin, end, ival.data)


class Publisher:
    def __init__(self):
        super().__init__()
        self.__subscribers = []

    def register_subscriber(self, s):
        self.__subscribers.append(s)

    def publish(self, meth, *args, **kwargs):
        for s in self.__subscribers:
            try:
                getattr(s, meth)(self, *args, **kwargs)
            except AttributeError:
                pass


class BaseAddrSpaceModel:
    def __init__(self, **kwds):
        super().__init__()
        self.size = 0
        self.mapd_size = 0
        self.allocd_size = 0
        self.__addr_ivals = IntervalMap.from_valued_interval_domain(AddrInterval(0, 2**64, None))

    @property
    def size_kb(self):
        return self.size // 2**10
    @property
    def size_mb(self):
        return self.size // 2**20

    @property
    def mapd_size_kb(self):
        return self.mapd_size // 2**10
    @property
    def mapd_size_mb(self):
        return self.mapd_size // 2**20


    def size_measured(self, size):
        self.size = size


    def _update(self, ival):
        overlaps = self.__addr_ivals[ival.begin-1 : ival.end+1]
        # XXX-LPT: use __init__ kwds.get('calc_amount_for_addr_ival_states', default=[])
        mapd_size_old = sum(((i.end - i.begin) for i in overlaps if i.state is AddrIntervalState.MAPD))
        allocd_size_old = sum(((i.end - i.begin) for i in overlaps if i.state is AddrIntervalState.ALLOCD))
        self.__addr_ivals.add(ival)
        overlaps = self.__addr_ivals[ival.begin-1 : ival.end+1]
        mapd_size_new = sum(((i.end - i.begin) for i in overlaps if i.state is AddrIntervalState.MAPD))
        allocd_size_new = sum(((i.end - i.begin) for i in overlaps if i.state is AddrIntervalState.ALLOCD))

        self.mapd_size += mapd_size_new - mapd_size_old
        self.allocd_size += allocd_size_new - allocd_size_old

        #print('{0}\t_update_map with {1}\n\tmapd_size_old={2} mapd_size_new={3} self.mapd_size={4}'
        #      .format(run.timestamp, ival, mapd_size_old, mapd_size_new, self.mapd_size), file=sys.stderr)


class AllocatorAddrSpaceModel(BaseAddrSpaceModel, Publisher):
    def __init__(self):
        super().__init__()
        self._addr_ivals = IntervalTree()


    def allocd(self, begin, end):
        interval = AddrInterval(begin, end, AddrIntervalState.ALLOCD)
        overlaps = self._addr_ivals[begin:end]
        overlaps_allocd = [o for o in overlaps if o.state is AddrIntervalState.ALLOCD]
        overlaps_freed = [o for o in overlaps if o.state is AddrIntervalState.FREED]
        if overlaps_allocd:
            print('{0}\tE: New allocation {1} overlaps existing allocations {2}, chopping them out'
                 .format(run.timestamp, interval, overlaps_allocd), file=sys.stderr)

            #interval_at_begin = self._addr_ivals[begin]
            #assert len(interval_at_begin) <= 1, 'Bug: overlapping address intervals at {0:x} {1}'
            #                                    .format(begin, interval_at_begin)
            #if interval_at_begin:
            #    interval_at_begin = interval_at_begin.pop()
            #    if interval_at_begin.state is AddrI

        if overlaps_freed:
            self.publish('reused', begin, end)
        if overlaps:
            self._addr_ivals.chop(begin, end)
        super()._update(interval)
        self._addr_ivals.add(interval)


    def reallocd(self, begin_old, begin_new, end_new):
        interval_old = intervaltree_query_checked(self._addr_ivals, begin_old)
        if not interval_old:
            print('{0}\tW: No existing allocation to realloc at {1:x}, doing just alloc'
                  .format(run.timestamp, begin_old), file=sys.stderr)

            self.allocd(begin_new, end_new)
            return
        if interval_old.state is not AddrIntervalState.ALLOCD:
            print('{0}\tE: Realloc of non-allocated interval {1}, assuming it is allocated'
                  .format(run.timestamp, interval_old), file=sys.stderr)
            pass

        # Free the old allocation, just the part that does not overlap the new allocation
        interval_new = AddrInterval(begin_new, end_new, AddrIntervalState.ALLOCD)
        if interval_new.overlaps(interval_old):
            super()._update(AddrInterval(interval_old.begin, interval_old.end, AddrIntervalState.FREED))
            self._addr_ivals.remove(interval_old)
            if interval_new.lt(interval_old):
                self._addr_ivals.add(AddrInterval(interval_new.end, interval_old.end, AddrIntervalState.FREED))
            if interval_new.gt(interval_old):
                self._addr_ivals.add(AddrInterval(interval_old.begin, interval_new.begin, AddrIntervalState.FREED))
        else:
            self.freed(begin_old)

        self.allocd(begin_new, end_new)


    def freed(self, begin):
        interval = intervaltree_query_checked(self._addr_ivals, begin)
        if interval:
            self._addr_ivals.remove(interval)
            if begin != interval.begin or interval.state is not AddrIntervalState.ALLOCD:
                print('{0}\tW: Freed({1:x}) misfrees {2}'.format(run.timestamp, begin, interval), file=sys.stderr)
            interval = AddrInterval(interval.begin, interval.end, AddrIntervalState.FREED)
        else:
            print('{0}\tW: No existing allocation to free at {1:x}, defaulting to one of size 1'
                  .format(run.timestamp, begin), file=sys.stderr)
            interval = AddrInterval(begin, begin + 1, AddrIntervalState.FREED)
        super()._update(interval)
        self._addr_ivals.add(interval)


    def revoked(self, begin, end):
        intervals = self._addr_ivals[begin:end]
        intervals_allocd = [ival for ival in intervals if ival.state is AddrIntervalState.ALLOCD]
        assert not intervals_allocd, 'Bug: revoking address intervals between {0:x}-{1:x} that are still allocated {2}'\
                                  .format(begin, end, intervals_allocd)

        ival = AddrInterval(begin, end, AddrIntervalState.REVOKED)
        super()._update(ival)
        self._addr_ivals.chop(ival.begin, ival.end)
        self._addr_ivals.add(ival)


class AddrSpaceModel(BaseAddrSpaceModel):
    def mapd(self, begin, end):
        self._update(AddrInterval(begin, end, AddrIntervalState.MAPD))

    def unmapd(self, begin, end):
        self._update(AddrInterval(begin, end, AddrIntervalState.UNMAPD))


class AllocationStateSubscriber:
    def reused(self, alloc_state, begin, end):
        raise NotImplemented


class BaseSweepingRevoker(AllocationStateSubscriber):
    def __init__(self, capacity_ivals=2**64):
        super().__init__()
        self.swept = 0
        self.sweeps = []
        self._capacity_ivals = int(capacity_ivals)


    @property
    def swept_mb(self):
        return self.swept // 2**20

    @property
    def swept_gb(self):
        return self.swept // 2**30


    # XXX-LPT: pack into sweeps of L addr_ivals, where L is an imposed limit
    def _sweep(self, amount, addr_ivals):
        if len(addr_ivals) > self._capacity_ivals:
            raise ValuError('{0} exceeds the limit for intervals at once ({1})'
                            .format(len(addr_ivals), self._capacity_ivals))

        # XXX: can I format AddrInterval like [x+mb]
        ts_str = '{0:>' + str(len(str(run.timestamp))) + '}'
        if hasattr(self, '_ns_last_print'):
            delta_ns = run.timestamp_ns - self._ns_last_print
            if delta_ns > 10**9:
                delta_str = str(delta_ns // 10**9) + 's' 
            elif delta_ns > 10**6:
                delta_str = str(delta_ns // 10**6) + 'ms'
            elif delta_ns > 10**3:
                delta_str = str(delta_ns // 10**3) + 'us'
            else:
                delta_str = str(delta_ns) + 'ns'
            ts_str = ts_str.format('+' + delta_str)
        else:
            ts_str = ts_str.format(run.timestamp)
        #print('{0}\tSweep {1:d}MB revoking references to {2} intervals'.format(ts_str, amount // 2**20, addr_ivals),
        #      file=sys.stdout)
        print_update()
        self._ns_last_print = run.timestamp_ns

        self.swept += amount
        self.sweeps.append((run.timestamp_ns, amount))


class NaiveSweepingRevoker(BaseSweepingRevoker):
    # XXX-LPT refactor private attribute access
    def reused(self, alloc_state, begin, end):
        intervals = [i for i in alloc_state._addr_ivals[begin:end] if i.state is AddrIntervalState.FREED]
        if intervals:
            self._sweep(addr_space.size, intervals)
        for ival in intervals:
            alloc_state.revoked(ival.begin, ival.end)


class CompactingSweepingRevoker(BaseSweepingRevoker):
    # XXX-LPT refactor private attribute access
    def reused(self, alloc_state, begin, end):
        intervals = [i for i in alloc_state._addr_ivals if i.state is AddrIntervalState.FREED]
        intervals.sort(reverse=True)
        intervals_coalesced = []

        while intervals:
            ival = intervaltree_query_coalesced(alloc_state._addr_ivals, intervals.pop().begin,
                                                coalesce_with={AddrIntervalState.REVOKED})
            intervals_coalesced.append(ival)
            while intervals and ival.end >= intervals[-1].begin:
                assert ival.end > intervals[-1].begin, '{0} failed to coalesce with {1}'.format(ival, intervals[-1])
                intervals.pop()

        if intervals_coalesced:
            self._sweep(addr_space.size, intervals_coalesced)
        for ival in intervals_coalesced:
            alloc_state.revoked(ival.begin, ival.end)


class Run:
    def __init__(self, file, **kwds):
        self.timestamp = 0
        self._ts_initial = 0
        self._file = file
        self._trace_listeners = kwds.get('trace_listeners', [])
        self._addr_space_sample_listeners = kwds.get('addr_space_sample_listeners', [])


    @property
    def timestamp_ns(self):
        return self.timestamp
    @property
    def timestamp_us(self):
        return self.timestamp // 10**3
    @property
    def timestamp_ms(self):
        return self.timestamp // 10**6

    @property
    def duration(self):
        return (self.timestamp - self._ts_initial) if self._ts_initial else 0
    @property
    def duration_us(self):
        return self.duration // 10**3
    @property
    def duration_ms(self):
        return self.timestamp // 10**6


    def replay(self):
        for line in self._file:
            if line.startswith('#'):
                continue

            ts, rest = line.split('\t', maxsplit=1)
            timestamp = int(ts)
            if not self._ts_initial:
                self._ts_initial = timestamp
            self.timestamp = timestamp

            if rest.count('\t') > 1:
                self._parse_trace(rest)
            else:
                self._parse_addr_space_sample(rest)


    def _parse_trace(self, line):
        _, call, arg, res = line.split('\t')
        arg = arg.split(' '); arg.insert(0, 0) # 1-indexed

        if call == 'malloc':
            begin = int(res, base=16)
            end = begin + int(arg[1])
        elif call == 'calloc':
            begin = int(res, base=16)
            end = begin + int(arg[1]) * int(arg[2])
        elif call == 'aligned_alloc':
            begin = int(res, base=16)
            end = begin + int(arg[2])
        elif call == 'posix_memalign':
            begin = int(res, base=16)
            end = begin + int(arg[2])
        elif call == 'realloc':
            begin_old = int(arg[1], base=16)
            begin_new = int(res, base=16)
            end_new = begin_new + int(arg[2])
        elif call == 'free':
            begin = int(arg[1], base=16)
        elif call == 'mmap':
            begin = int(res, base=16)
            end = begin + int(arg[2])
        elif call == 'munmap':
            begin = int(arg[1], base=16)
            end = begin + int(arg[2])

        #assert begin != 0, 'timestamp={6} call={0} arg1={1} arg2={2} res={3}\tbegin={4} end={5}'.format(call, arg1, arg2, res, begin, end, timestamp)

        if call in ('malloc', 'calloc', 'aligned_alloc', 'posix_memalign'):
            meth = 'allocd'
            args = (begin, end)
        elif call in ('realloc', ):
            if begin_old == 0:
                meth = 'allocd'
                args = (begin_new, end_new)
            elif end_new - begin_new == 0:
                meth = 'freed'
                args = (begin_old, )
            else:
                meth = 'reallocd'
                args = (begin_old, begin_new, end_new)
        elif call in ('free', ):
            meth = 'freed'
            args = (begin, )
        elif call in ('mmap', ):
            meth = 'mapd'
            args = (begin, end)
        elif call in ('munmap', ):
            meth = 'unmapd'
            args = (begin, end)
        else:
            raise ValueError('unknown call trace "{0}"'.format(call))

        for tl in self._trace_listeners:
            try:
                getattr(tl, meth)(*args)
            except AttributeError:
                pass


    def _parse_addr_space_sample(self, line):
        size = int(line)
        for sl in self._addr_space_sample_listeners:
            sl.size_measured(size)


def print_update():
    print('{0}\t{1}\t{2}\t{3}\t{4}'.format(run.timestamp, addr_space.size, addr_space.mapd_size,
          alloc_state.allocd_size, revoker.swept), file=sys.stdout)
print('#{0}\t{1}\t{2}\t{3}\t{4}'.format('timestamp', 'addr-space-total', 'addr-space-mapped',
      'allocator-allocd', 'allocator-swept'))

alloc_state = AllocatorAddrSpaceModel()
addr_space = AddrSpaceModel()
revoker_cls = globals()[sys.argv[1]]
revoker = revoker_cls(*sys.argv[2:])
alloc_state.register_subscriber(revoker)

run = Run(sys.stdin,
          trace_listeners=[alloc_state, addr_space],
          addr_space_sample_listeners=[addr_space, ])
run.replay()


'''
print('----', file=sys.stdout)
print('{0} swept {1}GB in {2} sweeps in a {3}s run trace\n'
      .format(type(revoker).__name__, revoker.swept_gb, len(revoker.sweeps), run.duration // 10**9), file=sys.stdout)

print('                          Sweep amount per time until next sweep', file=sys.stdout)
sweeps_sweep_per_s = [(s // (t2 - t1)) * 10**9 for (t1, s), (t2, _) in zip(revoker.sweeps, revoker.sweeps[1:]) if t2 - t1 > 0]
bins_gb = (0, 1, 2, 4, 8, 16, 32, 64)
# XXX-LPT do the returned bins match bins_gb?
freqs, bins = numpy.histogram(sweeps_sweep_per_s, bins=[g * 2**30 for g in bins_gb])
for bin_low, bin_high, freq in zip(bins_gb, bins_gb[1:], freqs):
    print('{0:2} - {1:2} GB/s  | {2:<50} {3}'.format(bin_low, bin_high, '=' * int((freq / len(sweeps_sweep_per_s)) * 50),
          freq), file=sys.stdout)

print('                                  Sweep amount histogram', file=sys.stdout)
bins_mb = (0, 64, 128, 256, 512, 1024, 2048, 4096, 8192)
freqs, bins = numpy.histogram(revoker.sweeps, bins=[m * 2**20 for m in bins_mb])
for bin_low, bin_high, freq in zip(bins_mb, bins_mb[1:], freqs):
    print('{0:4} - {1:4} MB  | {2:<50} {3}'.format(bin_low, bin_high, '=' * int((freq / len(revoker.sweeps)) * 50),
          freq), file=sys.stdout)
'''
