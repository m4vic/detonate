def render_table(rows):
    return "\n".join(" | ".join(row) for row in rows)


print(render_table([["name", "score"], ["alice", "92"], ["bob", "81"]]))
