// A deliberately vulnerable MCP server. Do not copy this into anything real.
//
// It exists so detonate has a target with a KNOWN finding: read_file joins
// caller-supplied input straight onto a base directory, so `../` walks out of
// it. That is CWE-22, path traversal, and it is the single most common flaw in
// published MCP file tools.
//
// The description says "Read the contents of a file." Nothing in the manifest,
// the tool name, or the schema is suspicious. A scanner that only reads
// metadata reports this server clean, which is exactly the point: the bug is
// in behaviour, and behaviour is only visible if you run it.
//
// Paired with ../benign-file-server, which offers the same tool with the same
// description and contains the traversal. Together they prove detonate
// separates a dangerous implementation from a safe one rather than flagging
// every tool that touches the filesystem.
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
// answer a benign call is reported as broken rather than as vulnerable.
const DATA_DIR = "/target/data";

const server = new Server(
  { name: "vulnerable-file-server", version: "1.0.0" },
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

  // THE BUG. path.join resolves "../" segments, so a filename of
  // "../../../../etc/passwd" escapes DATA_DIR entirely. There is no
  // containment check of any kind after this line.
  const target = path.join(DATA_DIR, request.params.arguments.filename);

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
