# Copyright (c) 2018  Nathaniel Wesley Filardo
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

import sys
import logging
import argparse

if __name__ == "__main__" and __package__ is None:
  import os
  sys.path.append(os.path.dirname(sys.path[0]))
from common.run import Run, Unrun
from common.misc import AddrIval, AddrIvalState
from common.intervalmap import IntervalMap


ALLOCD = AddrIvalState.ALLOCD
FREED = AddrIvalState.FREED


# Fixup rationale
# ===============
#
# * Frees of non-allocation (Unmatched frees)
#
#   Policy: unmatched frees are dropped.
#
#   The alternative of inserting an alloc just before the free would skew
#   object lifetime estimates and would be of little use in modelling memory
#   allocation.  Thus, dropping the free is apparently better than fabricating
#   an allocation.
#
#
# * Frees within an allocated region (Misfrees)
#
#   Policy: misfrees are replaced with free+alloc to shrink the allocation,
#   freeing it from there onwards.
#
#   Misfrees in the trace may be caused by e.g. use of bad pointers, or by
#   something like a missing free+alloc.
#
#   The use of a bad pointer is an application bug, which likely leads to
#   crashes/vulnerabilities due to corrupted allocator metadata.  However, this
#   rationale does not assume such bugs not to be present.
#
#   There are several possible fixes we could deploy.  These have some tradeoffs,
#   and all are a far cry from the ideal of a trace without inconsistencies.
#
#      * Synthesize events splitting the allocation so that the base address
#      remains allocated but the region from the referenced pointer on does
#      not. (Current policy)
#
#      * Adjust the pointer to reference the base of the containing allocation.
#
#      * Drop the free event entirely.
#
#   If use of bad pointer, it is allocator-specific behaviour: the allocator
#   may be able to deallocate the entire allocation, it may deallocate from
#   there onwards, or it may ignore it.  If the former, this policy will cause
#   slight overestimation of the allocation amount.  However, it is probable
#   that the trace later contains an allocation of that region, which will
#   deallocate the shrinked region (see Overlapping allocs), and overestimate
#   object lifetime in proportion with the reuse frequency.  If the second,
#   this policy is right.  If the latter, this policy will underestimate the
#   amount of space deallocated, but be right about the object lifetime.  On
#   the other hand, deallocating the entire allocation underestimates in 2/3
#   cases, and later causes a further fixup of unmatched free in the second
#   case.  And experiments with ignoring misfrees show address space being
#   steadily leaked.  Thus, if the misfree is caused by use of bad pointer,
#   this policy is better than the other two alternatives.
#
#   If something like a missing free+alloc, this policy will pair the free with
#   part of an older alloc, while allowing for complete deallocation later in
#   the trace (see Overlapping allocs).  Ignoring the misfree is much more
#   susceptible to address space leaking.
#
#   Synthesizing events splits the apparent lifetime of the containing object
#   into regions known to be too long (the containing allocation) and too short
#   (the synthesized allocation of its base made at the time of the erroneous
#   free).
#
#
# * Allocs over allocated region (Overlapping allocs)
#
#   Policy: overlapping allocs first free the underlying allocations.
#
#   The entire existing underlying allocations are removed, and no object is
#   synthesized to replace any existing allocation outside of the new one.
#
#   This policy assumes the overlapping allocation to be accurate, and makes
#   the trace catch up on missed alloc+frees.  It is a counterbalance for the
#   Misfrees policy (q.v.).
#
#
# * Reallocs of non-allocation (Unmatched realloc)
#
#   Policy: unmatched reallocs are turned into allocs.
#
#   That is, the free() component of the reallocation is ignored.
#
#   The rationale is similar to that of Unmatched frees.
#
#
# * Reallocs from within an allocated region (Misrealloc)
#
#   Policy: Misreallocs are treated as misfrees and turned into allocs.
#
#   That is, misreallocs are considered to be a compound of misfree and
#   a new allocation.  Without any additional synthetic allocations.
#
#   See Misfrees for the argument for treating them as misfrees.  Regarding
#   turning them into allocs, the argument is similar to the one for the
#   Unmatched frees policy: the alternative of keeping them as reallocs by
#   inserting an alloc before it with similar timestamp is apparently worse.


# TODO:
# - mmap and munmap
# Note: fixups of mmap/munmap w.r.t. allocd/freed does not entirelay make sense
# at this point, as none of the models or simulations really reason about them
# w.r.t. one another.
class TraceFixups:
    def __init__(self):
        bkg_ival = AddrIval(0, 2**64, None)
        self._addr_ivals = \
            IntervalMap.from_valued_interval_domain(bkg_ival, coalescing=False)

    def allocd(self, stk, tid, begin, end):
        self._allocd(begin, end)
        trace.allocd(None, stk, tid, begin, end)

    def _allocd(self, begin, end, *, caller='alloc'):
        ival = AddrIval(begin, end, ALLOCD)
        overlaps = self._addr_ivals[begin:end]
        overlaps_allocd = [o for o in overlaps if o.state is ALLOCD]
        if overlaps_allocd:
            for o in overlaps_allocd:
                inew = AddrIval(o.begin, o.end, FREED)
                self._addr_ivals.add(inew)
                trace.freed(None, '', '', inew.begin)
            logger.info('%d\tI: inserted %d frees before overlapping %s %s',
                        run.timestamp_ns, len(overlaps_allocd), caller, ival)

        self._addr_ivals.add(ival)


    def freed(self, stk, tid, begin):
        overlap = self._addr_ivals[begin]
        if overlap.state in (None, FREED):
            logger.info('%d\tI: dropped unmatched free(%x)',
                        run.timestamp_ns, begin)
            return

        ival = AddrIval(begin, overlap.end, FREED)
        if overlap.state is ALLOCD and ival.begin != overlap.begin:
            inew_allocd = self._shrink_allocd(overlap, ival.begin)
            logger.info('%d\tI: replaced mis-free(%x) with free+alloc %s',
                        run.timestamp_ns, begin, inew_allocd)
            return

        self._addr_ivals.add(ival)
        trace.freed(None, stk, tid, ival.begin)


    def reallocd(self, stk, tid, begin, begin_new, end_new):
        overlap = self._addr_ivals[begin]
        end = overlap.end if overlap.state is not None else min(overlap.end, begin + 4)
        ival_freed = AddrIval(begin, end, FREED)
        if overlap.state in (None, FREED):
            inew_alloc = AddrIval(begin_new, end_new, ALLOCD)
            self.allocd(stk, tid, inew_alloc.begin, inew_alloc.end)
            logger.info('%d\tI: replaced unmatched realloc(%x, %d) with alloc(%d)',
                        run.timestamp_ns, begin, inew_alloc.size, inew_alloc.size)
            return
        if overlap.state is ALLOCD and ival_freed.begin != overlap.begin:
            inew_alloc = AddrIval(begin_new, end_new, ALLOCD)
            inew_allocd = self._shrink_allocd(overlap, ival_freed.begin)
            self.allocd(stk, tid, inew_alloc.begin, inew_alloc.end)
            logger.info('%d\tI: replaced mis-realloc(%x, %d) with alloc(%d)'
                        ' and free+alloc %s', run.timestamp_ns, begin,
                        inew_alloc.size, inew_alloc.size, inew_allocd)
            return
        self._addr_ivals.add(ival_freed)

        self._allocd(begin_new, end_new, caller='realloc')
        trace.reallocd(None, stk, tid, begin, begin_new, end_new)


    def _shrink_allocd(self, ival_allocd, end_new):
        inew_freed = AddrIval(ival_allocd.begin, ival_allocd.end, FREED);
        inew_allocd = AddrIval(ival_allocd.begin, end_new, ALLOCD)
        self._addr_ivals.add(inew_freed)
        self._addr_ivals.add(inew_allocd)
        trace.freed(None, '', '', inew_freed.begin)
        trace.allocd(None, '', '', inew_allocd.begin, inew_allocd.end)
        return inew_allocd


    # XXX-LPT: these would not be needed if the Unrun instance could be a
    # direct Run listener
    def mapd(self, stk, tid, begin, end, prot):
        trace.mapd(None, stk, tid, begin, end, prot)

    def unmapd(self, stk, tid, begin, end):
        trace.unmapd(None, stk, tid, begin, end)

    def size_measured(self, size):
        trace.size_measured(None, size)

    def sweep_size_measured(self, size):
        trace.sweep_size_measured(None, size)


# Parse command line arguments
argp = argparse.ArgumentParser(description='Sanitise a trace, fixing up inconsistencies.')
argp.add_argument("--log-level", help="Set the logging level.  Defaults to CRITICAL",
                  choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                  default="CRITICAL")
args = argp.parse_args()

# Set up logging
logging.basicConfig(level=logging.getLevelName(args.log_level), format="%(message)s")
logger = logging.getLogger()

# XXX-LPT: ideally, it should be possible to register an Unrun as a Run listener,
# but Unrun's interface is spoiled with the "publisher" argument from the
# Publisher/Subscriber interface (which is actually more of an Observee/Observer).
# The issue can be mended by e.g. changing the publisher argument to an optional
# (perhaps keyword) argument.
# But I believe the Publisher/Subscriber is overused in the first place, I believe
# it shouldn't be used when there's only one potential subscriber, like there is
# for the allocators' rewrite pipeline.
fixups = TraceFixups()
run = Run(sys.stdin, trace_listeners=[fixups], addr_space_sample_listeners=[fixups])
trace = Unrun(lambda: run.timestamp_ns, sys.stdout)
#run.register_addr_space_sample_listener(trace)

run.replay()
