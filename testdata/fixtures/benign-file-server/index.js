// A safe MCP file server. The control for ../vulnerable-file-server.
//
// Same tool name, same description, same schema, same capability: it reads
// files from disk. The only difference is that it contains the path before
// touching it.
//
// This fixture is what stops detonate measuring capability as if it were
// malice. A scanner that reports "reads the filesystem" as a finding flags
// this server too, and a scanner that flags everything has said nothing. An
// earlier revision did exactly that to 30 of 59 real published skills.
//
// A scan of this server must report no findings AND complete coverage. Either
// half failing is a bug: a finding here is a false positive, and incomplete
// coverage means the probe never actually reached the tool.
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");
const fs = require("fs");
const path = require("path");

// detonate mounts the fixture read-only at /target inside the sandbox, so the
// data directory has to be addressed there. Pointing at a path that does not
// exist in the container would make every call fail, and a tool that cannot
// answer a benign call is reported as broken rather than as safe.
const DATA_DIR = "/target/data";

const server = new Server(
  { name: "benign-file-server", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "read_file",
      description: "Read the contents of a file.",
      inputSchema: {
        type: "object",
        properties: {
          filename: { type: "string", description: "Name of the file to read" },
        },
        required: ["filename"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== "read_file") {
    throw new Error(`unknown tool: ${request.params.name}`);
  }

  // THE FIX. Resolve to an absolute path first, then require that it is still
  // inside DATA_DIR. Checking the input for "../" instead would be weaker:
  // encodings and symlinks defeat string matching, while resolve() answers the
  // question that actually matters — where does this path end up?
  const target = path.resolve(DATA_DIR, request.params.arguments.filename);
  if (target !== DATA_DIR && !target.startsWith(DATA_DIR + path.sep)) {
    return {
      content: [{ type: "text", text: "error: path outside the data directory" }],
      isError: true,
    };
  }

  try {
    return { content: [{ type: "text", text: fs.readFileSync(target, "utf8") }] };
  } catch (err) {
    return {
      content: [{ type: "text", text: `error: ${err.message}` }],
      isError: true,
    };
  }
});

server.connect(new StdioServerTransport());
