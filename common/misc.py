# Publisher interface ------------------------------------------------- {{{

def _discard(*args, **kwargs): pass

class Publisher:
    def __init__(self):
        super().__init__()
        self.__subscribers = []

    def register_subscriber(self, s):
        self.__subscribers.append(s)

    def _publish(self, meth, *args, **kwargs):
        for s in self.__subscribers:
            getattr(s, meth, _discard)(self, *args, **kwargs)

# --------------------------------------------------------------------- }}}
# Data-structure utility functions ------------------------------------ {{{

# Insert the span [loc,loc+sz) into the list dl and store its node into
# dn[loc], but respect coalescing done by the intervalmap im.  Return the
# resulting span, too, for further processing.
def dll_im_coalesced_insert(loc, sz, im, dl, dn) :
  (qb, qsz, _) = im[loc]
  if loc != qb : # Coalesced left
    dl.remove(dn.pop(qb))
  if qb + qsz != loc + sz : # Coalesced right
    dl.remove(dn.pop(loc+sz))
  i = (qb,qsz)
  dn[qb] = dl.insert(i)
  return i

# Given two "iterator factories" which stream (base, length, value) tuples
# in increasing base order without overlaps, compute their intersection, in
# the form of another iterator streaming (base, length, (left value, right
# value)) tuples.  An iterator factory should begin iteration from the
# lowest possible value when given None and should return the span
# containing its argument, if that exists, or the first span thereafter.
# However, nothing will go wrong if the iterator factory simply returns the
# same iterator object to all requests, though things may be slower.
#
# This is most useful for merging two filtered views of IntervalMaps, and
# really shines when one or both of the maps contains large gaps in its
# filtered view, which give the opportunity to use the iterator factory to
# seek forward in the other stream.
def im_stream_inter(ifl, ifr) :
    (il, ir)     = (ifl(None), ifr(None))
    (bl, sl, vl) = next(il)
    (br, sr, vr) = next(ir)
    (nl, nr) = (bl, br)
    (inl, inr) = (False, False)

    c = min(nl, nr)
    if nl == c :
        inl = True
        nl = bl + sl
    if nr == c :
        inr = True
        nr = br + sr

    while True :

        n = min(nl, nr)

        if n != c and inl and inr :
            yield (c, n-c, (vl, vr))

        if n == nl :
            if inl and nl != bl :
                if not inr :
                   il = ifl(nr)
                (bl, sl, vl) = next(il)
                nl = bl
                inl = bl <= n < bl + sl
            else :
                nl = bl + sl
                inl = True
        if n == nr :
            if inr and nr != br :
                if not inl :
                   ir = ifr(nl)
                (br, sr, vr) = next(ir)
                nr = br
                inr = br <= n < br + sr
            else :
                nr = br + sr
                inr = True
        c = n


# --------------------------------------------------------------------- }}}

