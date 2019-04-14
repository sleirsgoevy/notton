import sys, collections, os, pickle

class DBDict(collections.UserDict):
    def __init__(self, dir, binary=False):
        self.dir = sys.argv[1]+'/'+dir
        os.makedirs(self.dir, exist_ok=True)
        self.binary = binary
        collections.UserDict.__init__(self)
        for k in os.listdir(self.dir):
            with open(self.dir+'/'+k, 'rb') as file:
                collections.UserDict.__setitem__(self, k, file.read() if self.binary else pickle.loads(file.read()))
    def __setitem__(self, key, value):
        collections.UserDict.__setitem__(self, key, value)
        with open(self.dir+'/'+key, 'wb') as file:
            if self.binary: file.write(value)
            else: file.write(pickle.dumps(value))
    def __delitem__(self, key):
        collections.UserDict.__delitem__(self, key)
        try: os.unlink(self.dir+'/'+key)
        except OSError: raise

class DBValue:
    def __init__(self, file):
        self.file = sys.argv[1]+'/'+file
        try:
            with open(self.file, 'rb') as file: self._data = pickle.loads(file.read())
        except IOError:
            with open(self.file, 'wb') as file: file.write(pickle.dumps(None))
            self._data = None
    @property
    def data(self): return self._data
    @data.setter
    def data(self, value):
        self._data = value
        with open(self.file, 'wb') as file: file.write(pickle.dumps(self._data))
