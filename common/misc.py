def discard(*args, **kwargs): pass

class Publisher:
    def __init__(self):
        super().__init__()
        self.__subscribers = []

    def register_subscriber(self, s):
        self.__subscribers.append(s)

    def _publish(self, meth, *args, **kwargs):
        for s in self.__subscribers:
            getattr(s, meth, discard)(self, *args, **kwargs)
