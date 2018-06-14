# Parser and driver for trace consumers

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
        elif call == 'revoke':
            begin = [int(b, base=16) for b in arg[1::2]]
            end = [int(e, base=16) for e in arg[2::2]]
            if len(begin) != len(end):
                raise ValueError('revoke call trace should have an even number of args, not {0}'
                                .format(len(begin) + len(end)))

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
        elif call in ('revoke', ):
            meth = 'revoked'
            args = tuple(zip(begin, end))
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


