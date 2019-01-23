import itertools
import sys

# Parser and driver for trace consumers

def _discard(*args, **kwargs): pass

class Run:
    def __init__(self, file, *, trace_listeners=[], addr_space_sample_listeners=[]):
        self._file = file

        self._trace_listeners = list(set(trace_listeners))
        self._addr_space_sample_listeners = list(set(addr_space_sample_listeners))

        self._record_types = dict()
        self.timestamp = 0
        self.alloc_api_calls = 0
        self._ts_initial = 0


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
        fields = line.split('\t')
        rtype, ts = fields[0], fields[1]
        rtype_spec = self._record_types.get(rtype, None)
        if not rtype_spec:
            raise ValueError('undeclared record type', rtype)

        self.timestamp = int(ts)
        fields = dict(zip(rtype_spec, fields))
        if rtype == 'aspace-sample':
            self._parse_addr_space_sample(fields)
        elif rtype == 'call-trace':
            self._parse_call_trace(fields)

    def replay(self):
        for line in self._file:
            if line.startswith('#'):
                continue
            line = line.strip('\n')
            if line.startswith('@record-type:'):
                self._parse_record_type(line)
                continue

            _, ts, _ = line.split('\t', maxsplit=2)
            self._ts_initial = int(ts)
            self._replay_line(line)
            break

        for line in self._file:
            if line.startswith('#'):
                continue
            line = line.strip('\n')
            if line.startswith('@record-type:'):
                self._parse_record_type(line)
                continue

            self._replay_line(line)

    def _parse_record_type(self, line):
        rtype_name, fields = line[13:].split('\t', maxsplit=1)
        self._record_types[rtype_name] = ('record-type\t' + fields).split('\t')


    def _parse_call_trace(self, event):
        call = event['name']
        arg = event['args'].split(' ')
        res = event['result']

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
            begin = int(arg[0], base=16)
            end = begin + int(arg[1])
        elif call == 'revoke':
            begin = [int(b, base=16) for b in arg[0::2]]
            end = [int(e, base=16) for e in arg[1::2]]
            if len(begin) != len(end):
                raise ValueError('revoke call trace should have an even number of args, not {0}'
                                .format(len(begin) + len(end)))

        #assert begin != 0, 'timestamp={6} call={0} arg1={1} arg2={2} res={3}\tbegin={4} end={5}'.format(call, arg1, arg2, res, begin, end, timestamp)

        if call == 'malloc' or \
           call == 'calloc' or \
           call == 'aligned_alloc' or \
           call == 'posix_memalign':
            meth = 'allocd'
            args = (begin, end)
            self.alloc_api_calls += 1
        elif call == 'realloc':
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
        elif call == 'free' :
            meth = 'freed'
            args = (begin, )
            self.alloc_api_calls += 1
        elif call == 'mmap' :
            meth = 'mapd'
            args = (begin, end, prot)
        elif call == 'munmap' :
            meth = 'unmapd'
            args = (begin, end)
        elif call == 'revoke' :
            meth = 'revoked'
            args = tuple(zip(begin, end))
        else:
            raise ValueError('unknown call trace "{0}"'.format(call))

        for tl in self._trace_listeners:
            getattr(tl, meth, _discard)(event, *args)

    def _parse_addr_space_sample(self, record):
        total_size = int(record['addr-space-size-b'])
        sweep_size = int(record['sweep-amount-b'])
        for sl in self._addr_space_sample_listeners:
            sl.aspace_sampled(record, total_size, sweep_size)


# Trace producer, a one-sided inverse of Run
# (in particular, Run o Unrun === id)

class Unrun:
    def __init__(self, tslam, out=sys.stdout):
        self._tslam = tslam
        self._out = out
        self._last_measured_size = None
        self._record_types = dict()

    def allocd(self, publ, event, begin, end, align=None):
        event = dict(event)
        call = event['name']
        size = end - begin
        if call == 'malloc':
            event['args'] = str(size)
        elif call == 'calloc':
            arg = event['args'].split(' ')
            if int(arg[0]) * int(arg[1]) != size:
                event['args'] = '{0:d} {1:d}'.format(1, size)
        elif call == 'aligned_alloc' or call == 'posix_memalign':
            if align is None:
                align = int(event['args'].split(' ')[0])
            event['args'] = '{0:d} {1:d}'.format(align, size)
        else:
            event['name'] = 'malloc'
            event['args'] = str(size)

        event['result'] = '{0:x}'.format(begin)
        if align is not None and begin & (~begin + 1) < align:
            raise ValueError('badly aligned alloc', event)

        self._synthesize_record(event)

    def freed(self, publ, event, begin):
        event = dict(event)
        event['name'] = 'free'
        event['args'] = '{0:x}'.format(begin)
        event['result'] = ''
        self._synthesize_record(event)

    def reallocd(self, publ, event, begin_old, begin_new, end_new):
        event = dict(event)
        event['name'] = 'realloc'
        event['args'] = '{0:x} {1:d}'.format(begin_old, end_new - begin_new)
        event['result'] = '{0:x}'.format(begin_new)
        self._synthesize_record(event)

    def mapd(self, publ, event, begin, end, prot):
        event = dict(event)
        if event['name'] == 'mmap':
            arg = event['args'].split(' ')
            arg[1] = str(end - begin)
            arg[2] = str(prot)
        else:
            event['name'] = 'mmap'
            arg = ['0', str(end - begin), str(prot), '1000', '-1', '0']
        event['args'] = ' '.join(arg)
        event['result'] = '{0:x}'.format(begin)
        self._synthesize_record(event)

    def unmapd(self, publ, event, begin, end):
        event = dict(event)
        event['name'] = 'munmap'
        event['args'] = '{0:x} {1:d}'.format(begin, end - begin)
        event['result'] = ''
        self._synthesize_record(event)

    def revoked(self, publ, event, *spans):
        event = dict(event)
        event['name'] = 'revoke'
        event['args'] = ' '.join('{0:x} {1:x}'.format(b, e) for b, e in spans)
        event['result'] = ''
        self._synthesize_record(event)


    def aspace_sampled(self, publ, record, size, sweep_size):
        record = dict(record)
        record['addr-space-size-b'] = str(size)
        record['sweep-amount-b'] = str(sweep_size)
        self._synthesize_record(record)


    def _synthesize_record(self, record):
        rtype_name = record['record-type']
        rtype_spec = self._record_types.get(rtype_name, None)
        if not rtype_spec:
            rtype_spec = self._synthesize_record_type(record)

        print('\t'.join(record[fn] for fn in rtype_spec), file=self._out)

    def _synthesize_record_type(self, record):
        record_fnames = set(record.keys())

        rtype_field_name = 'record-type'
        rtype_spec = [rtype_field_name, ]
        record_fnames.remove(rtype_field_name)

        ts_field_name = [fn for fn in record_fnames if fn.startswith('timestamp')][0]
        rtype_spec.append(ts_field_name)
        record_fnames.remove(ts_field_name)

        rtype_spec.extend(record_fnames)

        rtype_name = record['record-type']
        self._record_types[rtype_name] = rtype_spec
        print('@record-type:{0}\t'.format(rtype_name) + '\t'.join(rtype_spec[1:]), file=self._out)
        return rtype_spec
