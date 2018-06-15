class Publisher:
    def __init__(self):
        super().__init__()
        self.__subscribers = []

    def register_subscriber(self, s):
        self.__subscribers.append(s)

    def _publish(self, meth, *args, **kwargs):
        for s in self.__subscribers:
            try:
                getattr(s, meth)(self, *args, **kwargs)
            except AttributeError:
                pass
