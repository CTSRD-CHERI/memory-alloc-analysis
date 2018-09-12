#!/usr/bin/python3
# Copyright (c) 2018  Lucian Paul-Trifu
# Copyright (c) 2018  Nathaniel Wesley Filardo
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


# An IntervalMap is a piecewise-constant functinon over some finite interval
# of the natural numbers.  IntervalMap(base, size, v) initializes a
# constant function wherein all integers in [base, base+size) have the value
# v.  Subsequent calls to mark(b, s, v) will update the sub-interval [b,b+s)
# to have value v.  Calling ._walk(start) is useful only as an integrity
# constraint checker; it returns where it got through the dictionary,
# starting at start and following consecutive spans.  If everything's gone
# well, that's base+size above.
#
# One can optionally register a .vcc (Value Change Callback) on an
# IntervalMap, which will be called with (old, new, location, size) whenever
# an interval is visited as part of a mark.  old == new implies a spurious
# change (and so the name is not necessarily precise, sorry).
#
# If this file is run as main, it will run a random test case generator,
# which has been very helpful in sussing out logic bugs, but I won't claim
# that it has made the code correct.

from collections import namedtuple
from sortedcontainers import SortedDict
import random

import sys

def _vcc_noop(vold, vnew, loc, sz):
    pass

class IntervalMap:
    @classmethod
    def from_valued_interval_domain(cls, ival, *, coalescing=True, **kwds):
        imap = cls(ival.begin, ival.end - ival.begin, ival.value, coalescing=coalescing, **kwds)
        imap._ival_type = type(ival)
        return imap

    def __init__(self, base, sz, v, *, coalescing=True, **kwds):
        self.vcc = kwds.get('vcc', _vcc_noop)
        self.d = SortedDict()
        self.d[base] = (sz, v)
        self._base, self._sz, self._v = base, sz, v
        # XXX-LPT: can I subclass instead of this bool?
        self._coalescing = coalescing


    def add(self, ival):
        self.mark(ival.begin, ival.end - ival.begin, ival.value)


    def should_return_ivals(meth):
        def meth_return_ival(self, *args, **kwds):
            ret = meth(self, *args, **kwds)
            if not hasattr(self, '_ival_type'):
                return ret
            if isinstance(ret, tuple):
                (base, sz, v) = ret
                return self._ival_type(base, base + sz, v)
            elif isinstance(ret, list):
                return [self._ival_type(base, base + sz, v) for (base, sz, v) in ret]
            else:
                return (self._ival_type(base, base + sz, v) for (base, sz, v) in ret)
        meth_return_ival.raw = meth
        return meth_return_ival


    @should_return_ivals
    def get(self, loc, **kwds):
        base, sz, v = self.__getitem__.raw(self, loc)
        values_coalesced = kwds.get('coalesce_with_values', set())
        coalesce_with_self_and_values = kwds.get('coalesce_with_self_and_values', set())
        if coalesce_with_self_and_values:
            values_coalesced.update(coalesce_with_self_and_values.union({v}))
        if not values_coalesced:
            return (base, sz, v)

        basel, _, vl = (base, sz, v)
        baser, szr, vr = (base, sz, v)
        #print('base={0:x} sz={1:x} v={2} values_coalesced={3}'.format(base, sz, v, values_coalesced), file=sys.stderr)
        try:
            basel, _, vl = self.__getitem__.raw(self, basel - 1)
            while vl in values_coalesced:
                base, sz = basel, base + sz - basel
                basel, _, vl = self.__getitem__.raw(self, basel - 1)
                #print('basel={0:x} sz= vl={1}'.format(basel, vl), file=sys.stderr)
        except ValueError:
            pass
        try:
            baser, szr, vr = self.__getitem__.raw(self, baser + szr)
            while vr in values_coalesced:
                sz = baser + szr - base
                baser, szr, vr = self.__getitem__.raw(self, baser + szr)
                #print('baser={0:x} baser+szr={1:x} vr={2}'.format(baser, baser + szr, vr), file=sys.stderr)
        except ValueError:
            pass

        return (base, sz, v)


    @should_return_ivals
    def __getitem__(self, loc):
        d = self.d
        if isinstance(loc, slice):
            if loc.start is None:
                loc = slice(self._base, loc.stop)
            if loc.stop is None:
                loc = slice(loc.start, self._base + self._sz)
            try:
                ret = [self.__getitem__.raw(self, loc.start), ]
            except ValueError:
                ret = []
            ret.extend(((base, *d[base]) for base in
                         d.irange(loc.start, loc.stop, inclusive=(False, False))))
            return ret
        else:
            if not self._base <= loc < self._base + self._sz:
                raise ValueError(loc)
            base = d.iloc[d.bisect_right(loc) - 1]
            return (base, *d[base])


    @should_return_ivals
    def __iter__(self):
        return ((base, sz, v) for base, (sz, v) in self.d.items())

    def irange(self, start, stop):
        if not self._base <= start < self._base + self._sz:
            raise StopIteration
        d = self.d
        base = d.iloc[d.bisect_right(start) - 1]
        yield (base, *d[base])

        for base in d.irange(start, stop, inclusive=(False, False)) :
            yield (base, *d[base])

    def mark(self, loc, sz, v, recursing=0):
        if not self._base <= loc < self._base + self._sz:
            raise ValueError(loc)
        d = self.d
        ix = d.bisect_left(loc)

        # print("%d spans in intervalmap; l=%x sz=%x v=%s", len(d), loc, sz, v)
    
        # Attributes of self
        szex = None
        vex = None
    
        # Coalescing flags
        couldcleft = False
        couldcright = False

        if loc in d:
            # Left-aligned change, try coalescing left after change
            if ix != 0 : couldcleft = True
            (szex, vex) = d[loc]
        elif ix != 0 :
            # Not left-aligned.  Update our notion of self
            ix = ix - 1
            k = d.iloc[ix]
            (szex, vex) = d[k]

            assert k < loc and k + szex > loc, 'Off the map (to the right?)'
    
            
            if v == vex :
                # Not left aligned, but spurious in this region
                if loc + sz - k > szex :
                    #            {     vcc      }
                    #                    { mark }
                    # |----------|-------|------|
                    # k         loc    k+szex  loc+sz
                    # print("Spurious [%d+%d] (in [%d+%d]), but pushing forward" % (loc, sz, k, szex))
                    self.vcc(vex, v, loc, sz)
                    # Recurse once to change the existing value
                    # XXX Here docleft required for correctness 
                    return self.mark(k+szex, loc + sz - k - szex, v, recursing + 1)
                else :
                    #            {  vcc  }
                    # |----------|-------|------|
                    # k         loc   loc+sz  k+szex
                    # print("Spurious [%d+%d] (in [%d+%d])" % (loc, sz, k, szex))
                    self.vcc(vex, v, loc, sz)
                    return
    
            # Split bin to put us in the left-aligned case and then shift self
            d[k] = (loc-k, vex)
            szex += k - loc
            d[loc] = (szex, vex)
            ix = ix + 1
        else :
            assert False, 'Off the map to the left'
     
        if sz == szex:
            if v == vex:
                # print("Spurious [%d+%d]" % (loc, sz))
                self.vcc(vex, v, loc, sz)
            else :
                # Replace region wholesale, coalesce in both directions
                d[loc] = (sz, v)
                if ix < len(d)-1 : couldcright = True
    
                self.vcc(vex, v, loc, sz)
        elif sz < szex:
            if v == vex:
                # print("Spurious [%d+%d] (up to +%d)" % (loc, sz, szex))
                sz = szex
            else :
                # Split this region, don't coalesce right
                d[loc] = (sz, v)
                d[loc+sz] = (szex-sz, vex)
    
                self.vcc(vex, v, loc, sz)
        else:
            # Update the current region
            if v == vex:
                # print("Spurious [%d+%d] (up to +%d), but continuing" % (loc, sz, szex))
                pass 
            else :
                # XXX-LPT: shouldn't this be sz?
                # --> no, expanding to the right and replacing next
                d[loc] = (szex, v)

            self.vcc(vex, v, loc, szex)

            while szex < sz:
                # Look one bin to the right, and absorb it if it's small
                # enough.  If it isn't, we'll break out and do one step
                # recursively, to split it up.

                # d[loc+szex] can only throw KeyError if loc+szex > lim, which is guarded against in the prelude
                (sznext, vnext) = d[loc+szex]
                #print('\tloc+szex={0:x} sznext={1:x} vnext={2}'.format(loc+szex, sznext, vnext), file=sys.stderr)
                if sznext <= sz - szex :
                    del d[loc+szex]
                    self.vcc(vnext, v, loc+szex, sznext)

                    szex += sznext
                    d[loc] = (szex, v)
                else :
                    break
            else:
                assert szex == sz, "Invariant szex <= sz broken, loop exited cleanly and szex={0} != sz={1}"\
                                   .format(szex, sz)
                #if ix < len(d)-1: couldcright = True

            if szex != sz :
                # XXX Here docleft required for correctness 
                self.mark(loc+szex, sz-szex, v, recursing + 1)
                (sz, _) = d[loc]

            couldcright = loc+sz in d

        if couldcright and self._coalescing:
            # print("PreRC", ix, d)
            kr = d.iloc[ix+1]
            (szr, vr) = d[kr]
            if vr == v:
                del d.iloc[ix+1]
                del d.iloc[ix]
                sz = sz + szr
                d[loc] = (sz, v)
                # print("RC", ix, d)
    
        if couldcleft and (self._coalescing or recursing):
            # print("PreLC", ix, d)
            kl = d.iloc[ix-1]
            (szl, vl) = d[kl]
            if vl == v:
                del d.iloc[ix]
                del d.iloc[ix-1]
                d[kl] = (szl+sz, v)
                # print("LC", ix, d)


    def _walk(self, l):
        d = self.d
        ix = d.bisect_left(l)
    
        while True :
            (sz, v) = d[l]
            assert sz > 0
    
            l = l + sz
            if l in d :
                (_, vn) = d[l]
                #assert vn != v
    
                ixn = d.bisect_left(l)
                assert ixn == ix + 1
                ix = ixn
            else :
                break
    
        return l

if __name__ == "__main__":
    def vcc(vex, v, loc, sz):
        print("Marking changed from %s to %s in [%d+%d]" % (vex,v,loc,sz))
    
    lim = 1000
    ops = 100000
    d = IntervalMap(0, lim, False)
    d.vcc = vcc
    
    for i in range(1,ops) :
        loc = random.randint(0,lim-1)
        sz  = random.randint(1,lim-loc)
        b   = random.choice([True, False])
        print ("Marking [%d+%d] %s" % (loc, sz, b))
        d.mark(loc, sz, b)
        print (d.d)
        assert d._walk(0) == lim
