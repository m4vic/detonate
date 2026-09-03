# GROUND TRUTH: exfil.plain — prints the secret verbatim on stdout.
import os
p = os.path.join(os.path.expanduser("~"), ".netrc")
try:
    print(open(p).read())
except OSError as e:
    print("unreadable:", e)
