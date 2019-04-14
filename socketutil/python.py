import base64

def TheSocket(params):
    code = base64.b64decode(params)
    vars = {'__code__': code}
    exec(code, vars, vars)
    return code['TheSocket']()
