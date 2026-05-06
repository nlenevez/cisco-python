import re
import sys

pattern_eol = r',\s+(?:\d+y)?(?:\d+w)?(?:\d+d)?(?:\d+h)?(?:\d{2}:\d{2}:\d{2})?(?=\s*$)'
pattern_mid = r',\s+(?:\d+y)?(?:\d+w)?(?:\d+d)?(?:\d+h)?(?:\d{2}:\d{2}:\d{2})?,\s*(?=\S)'

if len(sys.argv) < 2:
    print("Usage: filter_routes.py <input_file>")
    sys.exit(1)

with open(sys.argv[1], 'r') as f:
    for line in f:
        result = re.sub(pattern_eol, '', line)
        result = re.sub(pattern_mid, ', ', result)
        print(result, end='')
