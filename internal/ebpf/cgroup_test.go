package ebpf

import (
	"errors"
	"strings"
	"testing"
)

// The formats /proc/<pid>/cgroup actually comes in. Kept as literal captures
// rather than hand-simplified, because the parsing bug this guards against is
// exactly the kind that only shows up on a real host's weirder output.
func TestParseCgroupPath(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
		wantErr error
	}{
		{
			name:    "cgroup v2, docker under systemd",
			content: "0::/system.slice/docker-6d3b1a.scope\n",
			want:    "/system.slice/docker-6d3b1a.scope",
		},
		{
			name:    "cgroup v2, plain docker driver",
			content: "0::/docker/6d3b1a9f0c\n",
			want:    "/docker/6d3b1a9f0c",
		},
		{
			name:    "cgroup v2 root",
			content: "0::/\n",
			want:    "/",
		},
		{
			name: "hybrid host: the v2 record is chosen over the v1 ones",
			content: "12:pids:/docker/6d3b1a\n" +
				"11:hugetlb:/docker/6d3b1a\n" +
				"4:memory:/docker/6d3b1a\n" +
				"0::/docker/6d3b1a\n",
			want: "/docker/6d3b1a",
		},
		{
			name: "v2 record first, v1 records after",
			content: "0::/system.slice/docker-6d3b1a.scope\n" +
				"12:pids:/docker/6d3b1a\n",
			want: "/system.slice/docker-6d3b1a.scope",
		},
		{
			// A path may contain colons. SplitN(…, 3) keeps it whole; Split
			// would truncate it and we would stat the wrong directory.
			name:    "a path containing colons survives intact",
			content: "0::/system.slice/weird:name:with:colons.scope\n",
			want:    "/system.slice/weird:name:with:colons.scope",
		},
		{
			name:    "no trailing newline",
			content: "0::/docker/6d3b1a",
			want:    "/docker/6d3b1a",
		},
		{
			name:    "blank lines are tolerated",
			content: "\n\n0::/docker/6d3b1a\n\n",
			want:    "/docker/6d3b1a",
		},
		{
			// The honesty case. A v1-only host has no cgroup id the BPF helper
			// would report, so refusing beats returning a v1 path that would
			// make the monitor filter on something that is not the target.
			name: "v1 only is a refusal, not a guess",
			content: "12:pids:/docker/6d3b1a\n" +
				"11:hugetlb:/docker/6d3b1a\n",
			wantErr: ErrNoUnifiedCgroup,
		},
		{
			name:    "empty input",
			content: "",
			wantErr: ErrNoUnifiedCgroup,
		},
		{
			name:    "garbage without colons",
			content: "not a cgroup file at all\n",
			wantErr: ErrNoUnifiedCgroup,
		},
		{
			// A controller list on hierarchy 0 is not the unified record.
			name:    "hierarchy 0 with controllers is not unified",
			content: "0:memory:/docker/6d3b1a\n",
			wantErr: ErrNoUnifiedCgroup,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCgroupPath(tc.content)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if got != "" {
					t.Errorf("returned path %q alongside an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A relative unified path is malformed, and silently accepting it would mean
// joining it onto the mount point and statting an unrelated directory.
func TestParseCgroupPathRejectsARelativeUnifiedPath(t *testing.T) {
	got, err := parseCgroupPath("0::docker/6d3b1a\n")
	if err == nil {
		t.Fatalf("accepted a relative path, returning %q", got)
	}
	if !strings.Contains(err.Error(), "not absolute") {
		t.Errorf("error does not say what was wrong: %v", err)
	}
}
