package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func mkTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("normal.go", "package x\n")
	write("big.bin", string(make([]byte, 200)))
	write("node_modules/x.js", "evil\n")
	write("sub/keep.go", "package s\n")
	if err := os.Symlink(filepath.Join(root, "normal.go"), filepath.Join(root, "link.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "binary.dat"), []byte{'a', 'b', 0, 'c'}, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func names(fs []File) []string {
	var out []string
	for _, f := range fs {
		out = append(out, filepath.Base(f.Path))
	}
	return out
}

func TestWalkListsNormalSkipsExcluded(t *testing.T) {
	res, err := Walk(mkTree(t), WalkOptions{MaxBytes: 100, Excludes: []string{"**/node_modules/**"}})
	if err != nil {
		t.Fatal(err)
	}
	got := names(res.Files)
	for _, want := range []string{"normal.go", "keep.go", "binary.dat"} {
		if !slices.Contains(got, want) {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	for _, banned := range []string{"x.js", "big.bin", "link.go"} {
		if slices.Contains(got, banned) {
			t.Fatalf("must skip %s, got %v", banned, got)
		}
	}
}

func TestWalkMarksBinary(t *testing.T) {
	res, err := Walk(mkTree(t), WalkOptions{MaxBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Files {
		if filepath.Base(f.Path) == "binary.dat" && !f.Binary {
			t.Fatal("binary.dat must be flagged Binary")
		}
		if filepath.Base(f.Path) == "normal.go" && f.Binary {
			t.Fatal("normal.go must not be flagged Binary")
		}
	}
}

func TestWalkMissingRootErrors(t *testing.T) {
	if _, err := Walk(filepath.Join(t.TempDir(), "nope"), WalkOptions{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"5MB": 5 << 20, "512KB": 512 << 10, "1GB": 1 << 30, "100": 100} {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Fatalf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := ParseSize("bogus"); err == nil {
		t.Fatal("expected error")
	}
}
