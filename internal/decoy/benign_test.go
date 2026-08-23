package decoy

import "testing"

// The rule that fixed six of fourteen tools on the official filesystem server.
//
// A single benign value is wrong for half of a filesystem server: hand a file
// path to list_directory and a working tool answers isError, after which the
// whole tool is written off as target_error. The failure looks like a defect in
// the target and is entirely ours.
func TestBenignForPicksDirectoryOrFileByShape(t *testing.T) {
	env := &Environment{ContainerHome: "/home/detonate"}
	dir := env.WorkspaceDir()
	file := env.BenignInput()

	for _, tc := range []struct {
		tool, param, want, why string
	}{
		// The disambiguation that motivated this: the official MCP filesystem
		// server names the argument "path" on both, meaning a file in one and a
		// directory in the other. Only the operation separates them.
		{"read_file", "path", file, "reading a file wants a file"},
		{"list_directory", "path", dir, "listing wants a directory"},

		{"directory_tree", "path", dir, "tree walks a directory"},
		{"create_directory", "path", dir, "creates a directory"},
		{"search_files", "path", dir, "searches within a directory"},
		{"list_directory_with_sizes", "path", dir, "listing variant"},

		{"read_text_file", "path", file, "still a file"},
		{"get_file_info", "path", file, "still a file"},
		{"write_file", "path", file, "writes a file"},

		// An explicit parameter name wins even when the tool reads file-shaped.
		{"read_file", "directory", dir, "explicit parameter name"},
		{"upload", "folder_path", dir, "explicit parameter name"},

		// Unrelated tools fall back to the file path, because most tools take
		// files and a wrong directory is no better than a wrong file.
		{"send_email", "subject", file, "unrelated tool"},
		{"get_weather", "city", file, "unrelated tool"},
	} {
		if got := env.BenignFor(tc.tool, tc.param); got != tc.want {
			t.Errorf("BenignFor(%q, %q) = %q, want %q (%s)",
				tc.tool, tc.param, got, tc.want, tc.why)
		}
	}
}

// The workspace is the secret-free part of the decoy. Handing a tool the home
// directory instead would point it straight at the planted credentials, and a
// tool that then listed them would look like a thief for doing what it was
// asked.
func TestBenignValuesNeverPointAtPlantedSecrets(t *testing.T) {
	env, err := Plant(t.TempDir(), "/home/detonate")
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range []string{env.BenignInput(), env.WorkspaceDir()} {
		for _, tok := range env.Tokens {
			if v == tok.Path {
				t.Fatalf("benign value %q is a planted secret path", v)
			}
		}
		if v == env.ContainerHome {
			t.Fatalf("benign value %q is the home directory, which contains every decoy", v)
		}
	}

	// And the benign file itself must carry no token, or every tool that reads
	// it would be reported as leaking.
	if hits := env.Match(env.BenignInput()); len(hits) != 0 {
		t.Fatalf("the benign path matched a planted token: %+v", hits)
	}
}
