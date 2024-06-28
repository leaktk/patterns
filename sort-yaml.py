import re
import sys
import yaml

def sort_results(results):
    """
    The order of the results need to match for both.
    """
    if not results:
        return results

    keys = list(sorted(results[0].keys()))
    return list(sorted(results, key=lambda r: tuple(map(r.get, keys))))

print(yaml.dump(sort_results(yaml.load(sys.stdin, Loader=yaml.SafeLoader))))
