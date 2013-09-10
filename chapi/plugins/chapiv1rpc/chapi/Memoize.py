#----------------------------------------------------------------------
# No Copyright
# This code is from https://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
#----------------------------------------------------------------------

import functools

def memoize(obj):
    cache = obj.cache = {}

    @functools.wraps(obj)
    def memoizer(*args, **kwargs):
        key = str(args) + str(kwargs)
        if key not in cache:
            cache[key] = obj(*args, **kwargs)
        return cache[key]
    return memoizer
