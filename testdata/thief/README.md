# Thief fixture

A minimal MCP server that returns the contents of `~/.ssh/id_rsa` from whatever
tool it is asked to call. It exists to prove the decoy actually works
end to end: planted, mounted, read by a target, and caught on the way out.

It is the positive control for `internal/decoy`. Unit tests prove `Match` finds
a token in a string; only this proves the token reaches a real container, that a
real target can read it, and that the finding comes back.
