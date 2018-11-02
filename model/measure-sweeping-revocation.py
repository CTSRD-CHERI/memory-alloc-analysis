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

import argparse
import ast
from collections import namedtuple
import itertools
import logging
import math
import numpy
import re
import sys
import os

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(sys.path[0]))

from common.intervalmap import IntervalMap
from common.misc import Publisher
from common.misc import AddrIval, AddrIvalState
from common.run import Run

class BaseAddrSpaceModel:
    def __init__(self, **kwds):
        super().__init__()
        self.size = 0
        self.sweep_size = 0

    @property
    def size_kb(self):
        return self.size // 2**10
    @property
    def size_mb(self):
        return self.size // 2**20

    @property
    def sweep_size_kb(self):
        return self.sweep_size // 2**10
    @property
    def sweep_size_mb(self):
        return self.sweep_size // 2**20

    def size_measured(self, size):
        self.size = size
        output.update()

    def sweep_size_measured(self, sweep_size):
        self.sweep_size = sweep_size


class BaseIntervalAddrSpaceModel(BaseAddrSpaceModel):
    def __init__(self, *, calc_total_for_state):
        super().__init__()
        self.__addr_ivals = IntervalMap.from_valued_interval_domain(AddrIval(0, 2**64, None))
        self._total = 0
        self._calc_total_for_state = calc_total_for_state


    def _update(self, ival):
        overlaps_old = self.__addr_ivals[ival.begin-1 : ival.end+1]
        total_old = sum(i.size for i in overlaps_old if i.state is self._calc_total_for_state)

        self.__addr_ivals.add(ival)

        overlaps_new = self.__addr_ivals[ival.begin-1 : ival.end+1]
        total_new = sum(i.size for i in overlaps_new if i.state is self._calc_total_for_state)
        self._total += total_new - total_old
        output.update()


    def addr_ivals_coalesced_sorted(self, begin=None, end=None):
        if begin is not None and end is not None:
            return [i for i in self.__addr_ivals[begin:end] if i.value is not None]
        else:
            return [i for i in self.__addr_ivals if i.value is not None]

    def addr_ival_coalesced(self, point, **kwds):
        i = self.__addr_ivals.get(point, **kwds)
        return i if i.value is not None else None


class AllocatedAddrSpaceModel(BaseIntervalAddrSpaceModel, Publisher):
    def __init__(self):
        super().__init__(calc_total_for_state=AddrIvalState.ALLOCD)
        bkg_ival = AddrIval(0, 2**64, None)
        self.__addr_ivals = IntervalMap.from_valued_interval_domain(bkg_ival, coalescing=False)
        self._realloc_stubs = IntervalMap.from_valued_interval_domain(bkg_ival)


    @property
    def allocd_size(self):
        return self._total


    def allocd(self, stk, tid, begin, end):
        interval = AddrIval(begin, end, AddrIvalState.ALLOCD)
        overlaps = self.addr_ivals_sorted(begin, end)
        overlaps_allocd = [o for o in overlaps if o.state is AddrIvalState.ALLOCD]
        overlaps_freed = [o for o in overlaps if o.state is AddrIvalState.FREED]
        overlaps_stubs = [o for o in self._realloc_stubs[begin:end] if o.state is AddrIvalState.FREED]
        if overlaps_allocd:
            oa = overlaps_allocd
            logger.warning('%d\tW: New allocation %s overlaps existing allocations %s, chopping them out',
                 run.timestamp, interval, overlaps_allocd)
            for o in oa:
                self.__addr_ivals.remove(o)
            if oa[0].contains_point(interval.begin):
                left_stub = AddrIval(oa[0].begin, interval.begin, AddrIvalState.ALLOCD)
                self.__addr_ivals.add(left_stub)
            if oa[-1].contains_point(interval.end):
                right_stub = AddrIval(interval.end, oa[-1].end, AddrIvalState.ALLOCD)
                self.__addr_ivals.add(right_stub)

        if overlaps_stubs:
            err_fmt  = '%d\t%s: New allocation %s reuses old allocation stub from realloc '\
                       '(invalid revocation ahead)'
            if args.exit_on_unsafe:
                err_fmt += ', exiting as instructed by --exit-on-unsafe'
                logger.critical(err_fmt, run.timestamp, 'Crit', interval)
                sys.exit(1)
            else:
                logger.error(err_fmt, run.timestamp, 'E', interval)

        if overlaps_freed:
            if args.exit_on_reuse:
                logger.critical("%d\tCrit: New allocation %s re-uses %s, exiting as instructed "
                             "by --exit-on-reuse", run.timestamp, interval, overlaps_freed)
                sys.exit(1)
            self._publish('reused', stk, tid, begin, end)
        super()._update(interval)
        self.__addr_ivals.add(interval)


    def reallocd(self, stk, tid, begin_old, begin_new, end_new):
        interval_old = self.addr_ival(begin_old)
        if not interval_old:
            logger.warning('%d\tW: No existing allocation to realloc at %x, doing just alloc',
                  run.timestamp, begin_old)
            self.allocd(stk, begin_new, end_new)
            return
        if interval_old.state is not AddrIvalState.ALLOCD:
            logger.warning('%d\tW: Realloc of non-allocated interval %s, assuming it is allocated',
                  run.timestamp, interval_old)

        # If the realloc is in place, just remove the old allocation.  It is not
        # right to mark it as freed, because if the freed part is then reused,
        # an invalid revocation that is not aligned with the start of the
        # reallocated part is generated.  This event is reported as an error
        # instead (see allocd()), since it is allocator behaviour that cannot be
        # made safe.
        interval_new = AddrIval(begin_new, end_new, AddrIvalState.ALLOCD)
        if interval_new.begin == interval_old.begin:
            super()._update(AddrIval(interval_old.begin, interval_old.end, None))
            self.__addr_ivals.remove(interval_old)
            if interval_new.size < interval_old.size:
                ival_old_stub = AddrIval(interval_new.end, interval_old.end, AddrIvalState.FREED)
                self._realloc_stubs.add(ival_old_stub)
        else:
            # XXX use _freed and eliminate spurious W/E reporting
            self.freed(stk, begin_old)

        self.allocd(stk, begin_new, end_new)


    def freed(self, stk, tid, begin):
        interval = self.addr_ival(begin)
        if interval:
            if begin != interval.begin or interval.state is not AddrIvalState.ALLOCD:
                logger.warning('%d\tW: Freed(%x) misfrees %s', run.timestamp, begin, interval)
            interval = AddrIval(interval.begin, interval.end, AddrIvalState.FREED)
        else:
            logger.warning('%d\tW: No existing allocation to free at %x, defaulting to one of size 1',
                  run.timestamp, begin)
            interval = AddrIval(begin, begin + 1, AddrIvalState.FREED)
        super()._update(interval)
        self.__addr_ivals.add(interval)


    def revoked(self, stk, tid, *bes):
        if not isinstance(bes[0], tuple):
            bes = [(bes[0], bes[1])]
        query_and_overlaps = [((b, e), self.addr_ivals_sorted(b, e)) for b, e in bes]
        overlaps_allocd = [i for i in itertools.chain(*(overlaps for _, overlaps in query_and_overlaps))
                           if i.state is AddrIvalState.ALLOCD]
        if overlaps_allocd:
            logger.critical('%d\tBug: revoking address intervals that are still allocated %s',
                         run.timestamp, overlaps_allocd)
            sys.exit(1)
        misrevokes = [[i for i in overlaps if i.state is AddrIvalState.FREED and (i.begin < b or i.end > e)]
                      for (b, e), overlaps in query_and_overlaps]
        if any(misrevokes):
            query_and_misrevokes = list(zip((AddrIval(b, e, AddrIvalState.REVOKED)
                                             for (b, e), _ in query_and_overlaps), misrevokes))
            logger.critical('%d\tBug: revoking intervals that do not fully capture the underlying'
                            ' freed allocations %s', run.timestamp, query_and_misrevokes)
            sys.exit(1)

        for begin, end in bes:
            ival = AddrIval(begin, end, AddrIvalState.REVOKED)
            super()._update(ival)
            self.__addr_ivals.add(ival)
            self._realloc_stubs.remove(ival)


    def addr_ivals_sorted(self, begin=None, end=None):
        return [i for i in self.__addr_ivals[begin:end] if i.value is not None]

    def addr_ival(self, point, **kwds):
        i = self.__addr_ivals.get(point, **kwds)
        return i if i.value is not None else None


class MappedAddrSpaceModel(BaseIntervalAddrSpaceModel):
    def __init__(self):
        super().__init__(calc_total_for_state=AddrIvalState.MAPD)

    @property
    def mapd_size(self):
        return self._total

    def mapd(self, _, __, begin, end, ___):
        self._update(AddrIval(begin, end, AddrIvalState.MAPD))

    def unmapd(self, _, __, begin, end):
        self._update(AddrIval(begin, end, AddrIvalState.UNMAPD))


class AllocatorMappedAddrSpaceModel(MappedAddrSpaceModel):
    '''Tracks mapped/unmapped by the allocator for internal use'''

    @staticmethod
    def call_is_from_allocator(callstack):
       return any(callstack.find(frame) >= 0 for frame in ('malloc', 'calloc', 'realloc', 'free'))

    def mapd(self, callstack, tid, begin, end, prot):
        if prot == 0b11 and AMAS.call_is_from_allocator(callstack):
            self._update(AddrIval(begin, end, AddrIvalState.MAPD))

    # Inherits the unmapd() method, accepting unmaps that are also external to the allocator.
    # Such unmaps have an effect on the mapd_size if they target the allocator's mappings
AMAS = AllocatorMappedAddrSpaceModel

class AccountingAllocatedAddrSpaceModel(BaseAddrSpaceModel):
    def __init__(self):
        super().__init__()
        self._va2sz = {}
        self.allocd_size = 0
        self.mapd_size = 0

    def mapd(self, callstack, tid, begin, end, prot):
        if prot == 0b11 and AMAS.call_is_from_allocator(callstack):
            self.mapd_size += end - begin
        output.update()
    def unmapd(self, callstack, tid, begin, end):
        if AMAS.call_is_from_allocator(callstack):
            self.mapd_size -= end - begin

    def allocd(self, stk, tid, begin, end):
        sz = end - begin
        self._va2sz[begin] = sz
        self.allocd_size += sz
        output.update()
    def freed(self, stk, tid, begin):
        sz = self._va2sz.get(begin)
        if sz is not None :
            self.allocd_size -= sz
            del self._va2sz[begin]
    def reallocd(self, stk, tid, obegin, nbegin, nend):
        self.freed(stk, tid, obegin)
        self.allocd(stk, tid, nbegin, nend)

class AllocatedAddrSpaceModelSubscriber:
    def reused(self, alloc_state, stk, begin, end):
        raise NotImplementedError


class BaseSweepingRevoker(AllocatedAddrSpaceModelSubscriber):
    def __init__(self, sweep_capacity_ivals=2**64):
        super().__init__()
        self.sweeps = 0
        self.swept = 0
        self.swept_ivals = 0
        self._sweep_capacity_ivals = int(sweep_capacity_ivals)

    @property
    def swept_mb(self):
        return self.swept // 2**20

    @property
    def swept_gb(self):
        return self.swept // 2**30


    def revoked(self, stk, tid, *bes):
        self._sweep(addr_space.sweep_size, [AddrIval(b, e, AddrIvalState.FREED) for b, e in bes])


    def _sweep(self, amount, addr_ivals):
        rounds = len(addr_ivals) // self._sweep_capacity_ivals +\
                 (len(addr_ivals) % self._sweep_capacity_ivals != 0)
        if rounds > 1:
            logger.warning('{0}\tW: Revoker capacity exceeded, doing {1} revocation rounds instead',
                           run.timestamp, rounds)

        self.sweeps += rounds
        self.swept += amount * rounds
        self.swept_ivals += len(addr_ivals)
        output.update()


class SimpleSweepingRevoker(BaseSweepingRevoker):
    def reused(self, alloc_state, stk, tid, begin, end):
        intervals = [i for i in alloc_state.addr_ivals_sorted(begin, end) if i.state is AddrIvalState.FREED]
        if intervals:
            self._sweep(addr_space.sweep_size, intervals)
        for ival in intervals:
            alloc_state.revoked(stk, tid, ival.begin, ival.end)


class CompactingSweepingRevoker(BaseSweepingRevoker):
    def reused(self, alloc_state, stk, tid, begin, end):
        overlaps = [i for i in alloc_state.addr_ivals_sorted(begin, end) if i.state is AddrIvalState.FREED]
        olaps_coalesced = self._coalesce_sorted_freed_with_revoked(overlaps)

        if olaps_coalesced:
            incr = True
            addr_bck, addr_fwd = olaps_coalesced[0].begin, olaps_coalesced[-1].end
            while len(olaps_coalesced) < self._sweep_capacity_ivals and incr:
                delta = self._sweep_capacity_ivals - len(olaps_coalesced)
                ivals_prev = [i for i in
                              alloc_state.addr_ivals_sorted(addr_bck - 0x1000, addr_bck)
                              if i.state is AddrIvalState.FREED]
                ivals_prev = CompactingSweepingRevoker._coalesce_sorted_freed_with_revoked(ivals_prev)[:delta//2 + delta%2]
                ivals_next = [i for i in
                              alloc_state.addr_ivals_sorted(addr_fwd, addr_fwd + 0x1000)
                              if i.state is AddrIvalState.FREED]
                ivals_next = CompactingSweepingRevoker._coalesce_sorted_freed_with_revoked(ivals_next)[:delta//2]
                ivals_prev.extend(olaps_coalesced)
                ivals_prev.extend(ivals_next)
                olaps_coalesced = ivals_prev
                incr = (self._sweep_capacity_ivals - len(olaps_coalesced)) < delta
                addr_bck = min(addr_bck - 0x1000, olaps_coalesced[0].begin)
                addr_fwd = max(addr_fwd + 0x1000, olaps_coalesced[-1].end)
            self._sweep(addr_space.sweep_size, olaps_coalesced)
        for ival in olaps_coalesced:
            alloc_state.revoked(stk, tid, ival.begin, ival.end)


    @staticmethod
    def _coalesce_sorted_freed_with_revoked(ivals_sorted):
        ivals = ivals_sorted
        ivals.reverse()
        olaps_coalesced = []

        while ivals:
            ival = alloc_state.addr_ival_coalesced(ivals.pop().begin,
                                                   coalesce_with_self_and_values={AddrIvalState.REVOKED},
                                                   coalesce_beyond_values={None})
            olaps_coalesced.append(ival)
            while ivals and ival.end >= ivals[-1].begin:
                assert ival.end > ivals[-1].begin, '{0} failed to coalesce with {1}'.format(ival, ivals[-1])
                ivals.pop()

        return olaps_coalesced


class BaseOutput:
    def rate_limited_runms(call_period_ms):
        def _rate_limited_ms(meth):
            call_last_ms = 0
            def rate_limited_meth(self, *args):
                nonlocal call_last_ms
                if call_last_ms == 0 or run.timestamp_ms - call_last_ms > call_period_ms:
                    meth(self, *args)
                    call_last_ms = run.timestamp_ms
            return rate_limited_meth
        return _rate_limited_ms

    def rate_limited_run_alloc_api_calls(call_period_alloc_api_calls):
        def _rate_limited_run_alloc_api_calls(meth):
            call_last = 0
            def rate_limited_meth(*args):
                nonlocal call_last
                if call_last == 0 or run.alloc_api_calls - call_last > call_period_alloc_api_calls:
                    meth(*args)
                    call_last = run.alloc_api_calls
            return rate_limited_meth
        return _rate_limited_run_alloc_api_calls


    def update(self):
        raise NotImplementedError

    def end(self):
        raise NotImplementedError


class FileOutput(BaseOutput):
    def __init__(self, file):
        if isinstance(file, str):
            file = open(file, 'w')
        self._file = file

    def end(self):
        self._file.close()


class CompositeOutput(BaseOutput):
    def __init__(self, *outputs):
        super().__init__()
        self._outputs = outputs

    def update(self):
        for o in self._outputs:
            o.update()

    def end(self):
        for o in self._outputs:
            o.end()


class GraphOutput(FileOutput):
    def __init__(self, file):
        super().__init__(file)
        self._output_header()

    def _output_header(self):
        print('#{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}'.format('timestamp-unix-ns', 'addr-space-total-b',
              'addr-space-sweep-b', 'allocator-mapped-b', 'allocator-allocd-b', 'sweeps', 'swept-b',
              'swept-intervals'), file=self._file)

    @BaseOutput.rate_limited_runms(100)
    def update(self):
        print('{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}'.format(run.timestamp, addr_space.size,
              addr_space.sweep_size, alloc_addr_space.mapd_size, alloc_state.allocd_size, revoker.sweeps,
              revoker.swept, revoker.swept_ivals), file=self._file)


class AllocationMapOutput(FileOutput, AllocatedAddrSpaceModelSubscriber):
    POOL_MAX_ARTIFICIAL_GROWTH = 0x1000

    POOL_MAP_RESOLUTION_IN_SYMBOLS = 60


    def __init__(self, *args):
        super().__init__(*args)
        self._addr_ivals_reused = IntervalTree()
        alloc_state.register_subscriber(self)


    def reused(self, alloc_state, stk, tid, begin, end):
        self._addr_ivals_reused.add(AddrIval(begin, end, None))


    # XXX-LPT _output_header
    #def _output_header(self)


    @BaseOutput.rate_limited_runms(100)
    def update(self):
        pools = self._get_memory_pools()

        print('---', file=self._file)
        for p in pools:
            chunk_size, rem = p.size // AllocationMapOutput.POOL_MAP_RESOLUTION_IN_SYMBOLS,\
                              p.size % AllocationMapOutput.POOL_MAP_RESOLUTION_IN_SYMBOLS
            chunk_size, rem = (chunk_size, rem) if chunk_size > 0 else (p.size, 0)
            chunk_offsets = itertools.chain(range(0, rem * (chunk_size+1), chunk_size+1),
                                            range(rem * (chunk_size+1), p.size, chunk_size))
            chunks = [p.begin + co for co in chunk_offsets]
            chunk_states = (self._chunk_state(cb, ce) for cb, ce in
                            itertools.zip_longest(chunks, chunks[1:], fillvalue=p.end));
            chunk_states_str = ''.join(chunk_states)
            print('{0:x}-{1:x} {2:s} {3:d}'.format(p.begin, p.end, chunk_states_str, chunk_size), file=self._file)

        self._addr_ivals_reused.clear()


    @staticmethod
    def _get_memory_pools():
        ivals = [i for i in alloc_state.addr_ivals_coalesced_sorted() if i.state is not AddrIvalState.UNMAPD]
        ivals.reverse()

        pools = []
        while ivals:
            pool = []
            pool.append(ivals.pop())
            while ivals and (ivals[-1].begin - pool[-1].end < AllocationMapOutput.POOL_MAX_ARTIFICIAL_GROWTH):
                assert pool[-1].end <= ivals[-1].begin, 'Bug: overlapping intervals {0} {1}'\
                                                        .format(pool[-1], ivals[-1])
                pool.append(ivals.pop())
            pools.append(AddrIval(pool[0].begin, pool[-1].end, None))

        return pools


    def _chunk_state(self, cbegin, cend):
        #print('{0:x}-{1:x}'.format(cbegin, cend), file=self._file)
        csize = cend - cbegin
        coverlaps = alloc_state.addr_ivals_coalesced_sorted(cbegin, cend)
        if self._addr_ivals_reused.search(cbegin, cend):
            chunk_stat = '~'   # 'reused'  (could be just partially)
        elif all(i.state in (AddrIvalState.MAPD, AddrIvalState.UNMAPD,
                              AddrIvalState.FREED, AddrIvalState.REVOKED) for i in coverlaps):
            chunk_stat = '0'   # 'freed'
        elif all((i.state is AddrIvalState.ALLOCD) for i in coverlaps) and\
             sum((min(i.end, cend) - max(i.begin, cbegin)) for i in coverlaps) >= 0.80 * csize:
            chunk_stat = '#'   # 'allocd'
        else:
            chunk_stat = '='   # 'fragmented'
        return chunk_stat


class SweepEventsOutput(FileOutput):
    def __init__(self, file):
        super().__init__(file)
        self._alloc_api_calls = 0
        self._revoker_state_last = revoker.swept

        self._output_header()
        run.register_trace_listener(self)

    def _output_header(self):
        print('#{0}\t{1}'.format('eventstamp-alloc-api-calls-malloc-calloc-aligned_alloc-posix_memalign-realloc-free',
              'sweep-amount-b'), file=self._file)

    def update(self):
        if self._revoker_state_last != revoker.swept:
            sweep = revoker.swept - self._revoker_state_last
            print('{0}\t{1}'.format(run.alloc_api_calls, sweep), file=self._file)
            self._revoker_state_last = revoker.swept


class DirectoryOutput(BaseOutput):
    def __init__(self, dir):
        try:
            os.makedirs(dir, mode=0o700)
        except OSError:
            pass
        self._dir = dir

    def end(self): pass


class RenderedAllocationMapOutput(DirectoryOutput):
    st2color = {
      AddrIvalState.ALLOCD  : 0x00FF00,
      AddrIvalState.FREED   : 0xFF0000,
      AddrIvalState.REVOKED : 0xFFFFFF,
    }

    def __init__(self, dir, period, geom):
        super().__init__(dir)
        self.update = BaseOutput.rate_limited_run_alloc_api_calls(period)(self.update)
        self._geom = geom

    def update(self):
        addr_ivals = alloc_state.addr_ivals_sorted()
        if not addr_ivals:
            return

        now = run.timestamp_ns
        img = Image.new('RGB', self._geom)

        # Use the first address being tracked
        baseva = addr_ivals[0].begin

        # Just how big is this image, anyway?
        # Assume 16-byte alignment, so one pixel per 16 bytes.
        topva = baseva + img.width * img.height * 16

        # Extract Z order from image width
        zo = img.width.bit_length() << 1

        renderSpansZ(img, zo,
          (((i.begin - baseva) >> 4, (i.end - i.begin) >> 4, self.st2color[i.value])
            for i in addr_ivals))

        img.save("%s/%s.png" % (self._dir, now))


class FreedAddrIvalsHistogramOutput(DirectoryOutput):
    def __init__(self, dir, period):
        super().__init__(dir)
        self.update = BaseOutput.rate_limited_run_alloc_api_calls(period)(self.update)

    def update(self) :
        freeszs = [i.size for i in alloc_state.addr_ivals_sorted() if i.value == AddrIvalState.FREED]
        if not freeszs:
          return

        now = run.timestamp_ns

        bins = 2**(numpy.arange(math.floor(math.log2(min(freeszs))),math.ceil(math.log2(max(freeszs))),0.25))
        plt.hist(freeszs,bins=bins,log=True)
        plt.xlabel("Span size (log2 bytes)")
        plt.xscale('log')
        plt.ylabel("Count")
        plt.title("FREED span histogram at time %d" % now)
        plt.grid(True)
        plt.savefig("%s/%d.png" % (self._dir,now),bbox_inches='tight')
        plt.close()


# Parse command line arguments
argp = argparse.ArgumentParser(description='Model allocation from a trace and output various measurements')
argp.add_argument("--log-level", help="Set the logging level.  Defaults to CRITICAL",
                  choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                  default="ERROR")
argp.add_argument('revoker', nargs='?', default='CompactingSweepingRevoker',
                  help="Select the revoker type, or 'account' to assume error-free trace and speed up the"
                  " stats gathering.  Revoker types: NaiveSweepingRevokerN, CompactingSweepingRevokerN,"
                  " where N is the revoker capacity (in # of capabilities, defaults to 1024).")
argp.add_argument("--exit-on-reuse", action="store_true", help="Stop processing and exit with non-zero code "
                  "if the trace contains re-use of freed memory to which there are unrevoked references."
                  "  This option is used to verify that the allocation trace is free of memory reuse.")
argp.add_argument("--exit-on-unsafe", action="store_true", help="Stop processing and exit with non-zero code "
                  "if the trace contains unsafe allocation behaviour, such as reuse of old allocation stub "
                  "from a shrinking realloc.")

argp.add_argument("--allocation-map-output", help="Output file for the allocation map (disabled by default)")
argp.add_argument("--sweep-events-output", help="Output file for the sweep-triggering events (disabled by default)")
argp.add_argument("--rendered-allocation-map-output", type=str, help="Output directory for rendered "
                  "allocation maps (disabled by default)")
argp.add_argument('--rendered-allocation-map-geometry', type=ast.literal_eval, default=(1024,1024))
argp.add_argument('--rendered-allocation-map-period', type=int, default=10 * 10**6, help="Period in allocator "
                  "API calls between renderings of the allocation map output (enabled through "
                  "--rendered-allocation-map-output); defaults to 10M")
argp.add_argument('--freed-addr-ivals-histogram-output', type=str, help="Output directory for freed spans "
                  "histogram output (disabled by default)")
argp.add_argument('--freed-addr-ivals-histogram-period', type=int, default=1 * 10**6, help="Period in allocator "
                  "API calls between renderings of the freed spans histograms output (enabled through "
                  "freed-addr-ivals-histogram-output); defaults to 1M")

args = argp.parse_args()

# Set up logging
logging.basicConfig(level=logging.getLevelName(args.log_level), format="%(message)s")
logger = logging.getLogger()

# Check command-line arguments
if args.revoker == "account":
    if args.sweep_events_output:
        logger.critical('Crit: Sweep events cannot be output in accounting mode')
        sys.exit(1)
    if args.allocation_map_output or args.rendered_allocation_map_output:
        logger.critical('Crit: Allocation map cannot be output in accounting mode')
        sys.exit(1)
    if args.freed_addr_ivals_histogram_output:
        logger.critical('Crit: FREED intervals histogram cannot be output in accounting mode')
        sys.exit(1)

# Set up the model
if args.revoker == "account":
    alloc_state = AccountingAllocatedAddrSpaceModel()
    addr_space = alloc_state
    alloc_addr_space = addr_space
    revoker = BaseSweepingRevoker()
else:
    alloc_state = AllocatedAddrSpaceModel()
    addr_space = MappedAddrSpaceModel()
    alloc_addr_space = AllocatorMappedAddrSpaceModel()
    m = re.search('([a-zA-Z]+)([0-9]+)?', args.revoker)
    revoker_cls = globals()[m.group(1)]
    revoker = revoker_cls(*(m.group(2),) if m.group(2) is not None else (1024,))
    alloc_state.register_subscriber(revoker)

# Set up the input processing
run = Run(sys.stdin,
          trace_listeners=[alloc_state, addr_space, alloc_addr_space, revoker],
          addr_space_sample_listeners=[addr_space, ])

# Set up the output
output = GraphOutput(sys.stdout)
if args.allocation_map_output:
    alloc_map_output = AllocationMapOutput(args.allocation_map_output)
    output = CompositeOutput(output, alloc_map_output)
if args.sweep_events_output:
    sweep_events_output = SweepEventsOutput(args.sweep_events_output)
    output = CompositeOutput(output, sweep_events_output)
if args.rendered_allocation_map_output:
    from PIL import Image
    from PIL import ImageDraw
    from common.render import renderSpansZ
    rendered_alloc_map_output = RenderedAllocationMapOutput(args.rendered_allocation_map_output,
                                                            args.rendered_allocation_map_period,
                                                            args.rendered_allocation_map_geometry)
    output = CompositeOutput(output, rendered_alloc_map_output)
if args.freed_addr_ivals_histogram_output:
    import matplotlib.pyplot as plt
    freed_spans_hist_output = FreedAddrIvalsHistogramOutput(args.freed_addr_ivals_histogram_output,
                                                            args.freed_addr_ivals_histogram_period)
    output = CompositeOutput(output, freed_spans_hist_output)

run.replay()
output.update()  # ensure at least one output update
output.end()
