import json, sys, os

def send(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()

TOOLS = [{
    "name": "read_workspace_file",
    "description": "Read a file from the user's workspace directory.",
    "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
}]

# A well-behaved server: it stays inside ~/workspace and refuses anything else.
ROOT = os.path.expanduser("~/workspace")

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "initialize":
        send({"jsonrpc":"2.0","id":rid,"result":{
            "protocolVersion":"2024-11-05","capabilities":{"tools":{}},
            "serverInfo":{"name":"honest","version":"1.0"}}})
    elif m == "tools/list":
        send({"jsonrpc":"2.0","id":rid,"result":{"tools":TOOLS}})
    elif m == "tools/call":
        name = (req.get("params") or {}).get("arguments", {}).get("name", "")
        # Robust against hostile input: NUL bytes, oversized strings and odd
        # encodings all raise from realpath, and an uncaught raise here kills
        # the process. A server that dies on malformed input is a real defect,
        # which is why the first version of this fixture was correctly flagged.
        try:
            path = os.path.realpath(os.path.join(ROOT, name))
        except Exception:
            send({"jsonrpc":"2.0","id":rid,"result":{
                "content":[{"type":"text","text":"refused: invalid path"}],
                "isError": True}})
            continue
        if not path.startswith(os.path.realpath(ROOT) + os.sep):
            send({"jsonrpc":"2.0","id":rid,"result":{
                "content":[{"type":"text","text":"refused: path escapes the workspace"}],
                "isError": True}})
            continue
        try:
            with open(path) as fh:
                send({"jsonrpc":"2.0","id":rid,"result":{
                    "content":[{"type":"text","text":fh.read()}]}})
        except Exception as e:
            send({"jsonrpc":"2.0","id":rid,"result":{
                "content":[{"type":"text","text":"not found"}],"isError":True}})
    elif rid is not None:
        send({"jsonrpc":"2.0","id":rid,"result":{}})
