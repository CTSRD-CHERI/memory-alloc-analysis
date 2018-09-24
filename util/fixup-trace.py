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


# TODO:
# - mmap/munmap
#
# allocd/freed w.r.t. mmap/munmap does not entirelay make sense at this point,
# as none of the models or simulations use them w.r.t. one another

class TraceFixups:
    def __init__(self):
        bkg_ival = AddrIval(0, 2**64, None)
        self._addr_ivals = \
            IntervalMap.from_valued_interval_domain(bkg_ival, coalescing=False)


    def allocd(self, stk, begin, end):
        self._allocd(begin, end)
        trace.allocd(None, stk, begin, end)

    def _allocd(self, begin, end, *, caller='alloc'):
        ival = AddrIval(begin, end, ALLOCD)
        overlaps = self._addr_ivals[begin:end]
        overlaps_allocd = [o for o in overlaps if o.state is ALLOCD]
        if overlaps_allocd:
            ivals_new = []
            for o in overlaps_allocd:
                inew = AddrIval(o.begin, o.end, FREED)
                ivals_new.append(inew)
                self._addr_ivals.add(inew)
                trace.freed(None, '', inew.begin)
            if overlaps_allocd[0].begin < ival.begin:
                o = overlaps_allocd[0]
                inew = AddrIval(o.begin, ival.begin, ALLOCD)
                ivals_new.append(inew)
                self._addr_ivals.add(inew)
                trace.allocd(None, '', inew.begin, inew.end)
            if overlaps_allocd[-1].end > ival.end:
                o = overlaps_allocd[-1]
                inew = AddrIval(ival.end, o.end, ALLOCD)
                ivals_new.append(inew)
                self._addr_ivals.add(inew)
                trace.allocd(None, '', inew.begin, inew.end)
            reallocs = len(ivals_new) - len(overlaps_allocd)
            logger.info('%d\tI: inserted %d frees and free+alloc(s) %s before '
                        'overlaid %s %s', run.timestamp_ns,
                        len(overlaps_allocd) - reallocs, ivals_new[-reallocs:],
                        caller, ival)

        self._addr_ivals.add(ival)


    def freed(self, stk, begin):
        self._freed(begin)
        trace.freed(None, stk, begin)

    def _freed(self, begin, *, caller='free'):
        overlap = self._addr_ivals[begin]
        end = overlap.end if overlap.state is not None else min(overlap.end, begin + 4)
        ival = AddrIval(begin, end, FREED)

        if overlap.state in (None, FREED):
            ival_new = AddrIval(ival.begin, ival.end, ALLOCD)
            self._addr_ivals.add(ival_new)
            trace.allocd(None, '', ival_new.begin, ival_new.end)
            logger.info('%d\tI: inserted alloc before unmatched %s %s',
                        run.timestamp_ns, caller, ival)
        elif overlap.state is ALLOCD and ival.begin != overlap.begin:
            ivals_new = (AddrIval(overlap.begin, overlap.end, FREED),
                         AddrIval(overlap.begin, ival.begin, ALLOCD),
                         AddrIval(ival.begin, ival.end, ALLOCD))
            self._addr_ivals.add(*ivals_new)
            trace.freed(None, '', ivals_new[0].begin)
            trace.allocd(None, '', ivals_new[1].begin, ivals_new[1].end)
            trace.allocd(None, '', ivals_new[2].begin, ivals_new[2].end)
            logger.info('%d\tI: inserted free+alloc %s before mis%s %s',
                        run.timestamp_ns, ivals_new[1], caller, ival)

        self._addr_ivals.add(ival)


    def reallocd(self, stk, begin_old, begin_new, end_new):
        self._freed(begin_old, caller='realloc')
        self._allocd(begin_new, end_new, caller='realloc')
        trace.reallocd(None, stk, begin_old, begin_new, end_new)


    def size_measured(self, size):
        trace.size_measured(None, size)

    def sweep_size_measured(self, size):
        trace.sweep_size_measured(None, size)


# Parse command line arguments
argp = argparse.ArgumentParser(description='Model allocation from a trace and output various measurements')
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
