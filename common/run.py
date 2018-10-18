import itertools
import sys

# Parser and driver for trace consumers

def _discard(*args, **kwargs): pass

class Run:
    def __init__(self, file, *, trace_listeners=[], addr_space_sample_listeners=[]):
        self.timestamp = 0
        self.alloc_api_calls = 0
        self._ts_initial = 0
        self._file = file
        self._trace_listeners = list(set(trace_listeners))
        self._addr_space_sample_listeners = list(set(addr_space_sample_listeners))


    def register_trace_listener(self, *l):
        self._trace_listeners.extend(set(l) - set(self._trace_listeners))

    def register_addr_space_sample_listener(self, *l):
        self._addr_space_sample_listeners.extend(set(l) - set(self._addr_space_sample_listeners))


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

    @property
    def timestamp_initial_ns(self):
        return self._ts_initial

    def _replay_line(self, line) :
      ts, rest = line.split('\t', maxsplit=1)
      timestamp = int(ts)
      self.timestamp = timestamp

      fields = rest.split('\t')
      if len(fields) == 2:
          self._parse_addr_space_sample(fields)
      else:
          self._parse_trace(fields)

    def replay(self):
        for line in self._file:
            if line.startswith('#'):
                continue

            ts, rest = line.split('\t', maxsplit=1)
            self._ts_initial = int(ts)
            self._replay_line(line)
            break

        for line in self._file:
            if line.startswith('#'):
                continue

            self._replay_line(line)

    def _parse_trace(self, fields):
        callstack, call, arg, res = fields
        arg = arg.split(' ')

        if call == 'malloc':
            begin = int(res, base=16)
            end = begin + int(arg[0])
        elif call == 'calloc':
            begin = int(res, base=16)
            end = begin + int(arg[0]) * int(arg[1])
        elif call == 'aligned_alloc':
            begin = int(res, base=16)
            end = begin + int(arg[1])
        elif call == 'posix_memalign':
            begin = int(res, base=16)
            end = begin + int(arg[1])
        elif call == 'realloc':
            begin_old = int(arg[0], base=16)
            begin_new = int(res, base=16)
            end_new = begin_new + int(arg[1])
        elif call == 'free':
            begin = int(arg[0], base=16)
        elif call == 'mmap':
            begin = int(res, base=16)
            end = begin + int(arg[1])
            prot = int(arg[2])
        elif call == 'munmap':
            begin = int(arg[1], base=16)
            end = begin + int(arg[1])
        elif call == 'revoke':
            begin = [int(b, base=16) for b in arg[0::2]]
            end = [int(e, base=16) for e in arg[1::2]]
            if len(begin) != len(end):
                raise ValueError('revoke call trace should have an even number of args, not {0}'
                                .format(len(begin) + len(end)))

        #assert begin != 0, 'timestamp={6} call={0} arg1={1} arg2={2} res={3}\tbegin={4} end={5}'.format(call, arg1, arg2, res, begin, end, timestamp)

        if call in ('malloc', 'calloc', 'aligned_alloc', 'posix_memalign'):
            meth = 'allocd'
            args = (begin, end)
            self.alloc_api_calls += 1
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
            self.alloc_api_calls += 1
        elif call in ('free', ):
            meth = 'freed'
            args = (begin, )
            self.alloc_api_calls += 1
        elif call in ('mmap', ):
            meth = 'mapd'
            args = (begin, end, prot)
        elif call in ('munmap', ):
            meth = 'unmapd'
            args = (begin, end)
        elif call in ('revoke', ):
            meth = 'revoked'
            args = tuple(zip(begin, end))
        else:
            raise ValueError('unknown call trace "{0}"'.format(call))

        for tl in self._trace_listeners:
            getattr(tl, meth, _discard)(callstack, *args)

    def _parse_addr_space_sample(self, fields):
        total_size, sweep_size = [int(s) for s in fields]
        for sl in self._addr_space_sample_listeners:
            sl.size_measured(total_size)
            sl.sweep_size_measured(sweep_size)


# Trace producer, a one-sided inverse of Run
# (in particular, Run o Unrun === id)

class Unrun:
    def __init__(self, tslam, out=sys.stdout):
        self._tslam = tslam
        self._out = out
        self._last_measured_size = None

    def allocd(self, publ, stk, begin, end):
        # XXX we lose information about precisely which allocator call it was
        # (i.e. malloc vs. calloc vs. aligned_alloc vs. posix_memalign ....)
        print("%d\t%s\tmalloc\t%d\t%x" % (self._tslam(), stk, end - begin, begin), file=self._out)

    def freed(self, publ, stk, begin):
        print("%d\t\tfree\t%x\t" % (self._tslam(), begin), file=self._out)

    def reallocd(self, publ, stk, begin_old, begin_new, end_new):
        print("%d\t%s\trealloc\t%x %d\t%x" % (self._tslam(), stk, begin_old, end_new - begin_new, begin_new), file=self._out)

    def mapd(self, publ, stk, begin, end, prot):
        print("%d\t%s\tmmap\t0 %d %d\t%x" % (self._tslam(), stk, end - begin, prot, begin))

    def unmapd(self, publ, stk, begin, end):
        print("%d\t%s\tmunmap\t%x %d\t" % (self._tslam(), stk, begin, end - begin))

    def revoked(self, publ, stk, spans):
        print("%d\t\trevoke\t%s\t" % (self._tslam(),
            " ".join(["%x %x" % be for be in spans])))

    # These are packed onto one line, so cache them in the order generated
    # by Run.
    def size_measured(self, publ, size):
        self._last_measured_size = size

    def sweep_size_measured(self, publ, size):
        print("%d\t%d\t%d" % (self._tslam(), self._last_measured_size, size))
