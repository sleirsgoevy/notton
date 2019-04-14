import sys

@type.__call__
class frontend:
    def __init__(self):
        with open(sys.argv[2]) as file: code = file.read()
        exec(compile(code, sys.argv[2], 'exec'), self.__dict__, self.__dict__)
