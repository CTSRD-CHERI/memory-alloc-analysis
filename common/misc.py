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

# --------------------------------------------------------------------- }}}

