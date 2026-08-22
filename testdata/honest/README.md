# Honest fixture

A well-behaved MCP server: it reads files from `~/workspace`, refuses anything
that escapes it, and survives malformed input.

It is the negative control for the decoy. `testdata/thief` proves detonate
catches a leak; this proves it does not invent one — a scanner that only ever
gets tested against malicious targets will happily call everything malicious.

The first version of this fixture crashed on hostile input because it did not
guard `os.path.realpath`, and detonate flagged it eleven times. Those were true
positives: a server that dies on malformed input is a real defect. The guard was
added to the fixture, not the rule.
