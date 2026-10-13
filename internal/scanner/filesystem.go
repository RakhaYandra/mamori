// Package scanner walks the filesystem and detects secrets and risky permissions.
package scanner

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WalkOptions bounds a traversal.
type WalkOptions struct {
	MaxBytes       int64
	FollowSymlinks bool
	ScanHidden     bool
	Excludes       []string
}

// File is one scannable regular file.
type File struct {
	Path   string
	Size   int64
	Binary bool
}

// WalkResult separates scannable files from skips and partial failures.
type WalkResult struct {
	Files   []File
	Skipped []string
	Partial []error
}

// DefaultExcludes are always skipped.
var DefaultExcludes = []string{"**/.git/**", "**/node_modules/**", "**/vendor/**", "**/.cache/**"}

// Walk lists regular files under root without following symlinks by default.
func Walk(root string, opts WalkOptions) (WalkResult, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return WalkResult{}, fmt.Errorf("resolve root: %w", err)
	}
	if _, err := os.Lstat(abs); err != nil {
		return WalkResult{}, fmt.Errorf("stat root: %w", err)
	}
	literals := literalsOf(append(append([]string{}, DefaultExcludes...), opts.Excludes...))
	var res WalkResult
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			res.Partial = append(res.Partial, fmt.Errorf("%s: %w", p, err))
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if !opts.FollowSymlinks {
				res.Skipped = append(res.Skipped, p)
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			if p != abs && excluded(p, literals) {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(p, literals) {
			res.Skipped = append(res.Skipped, p)
			return nil
		}
		if !opts.ScanHidden && isHidden(p) {
			res.Skipped = append(res.Skipped, p)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			res.Partial = append(res.Partial, fmt.Errorf("%s: %w", p, err))
			return nil
		}
		if !info.Mode().IsRegular() {
			res.Skipped = append(res.Skipped, p)
			return nil
		}
		if opts.MaxBytes > 0 && info.Size() > opts.MaxBytes {
			res.Skipped = append(res.Skipped, p)
			return nil
		}
		bin, err := IsBinary(p)
		if err != nil {
			res.Partial = append(res.Partial, fmt.Errorf("%s: %w", p, err))
			return nil
		}
		res.Files = append(res.Files, File{Path: p, Size: info.Size(), Binary: bin})
		return nil
	})
	if err != nil {
		return WalkResult{}, err
	}
	return res, nil
}

// literalsOf reduces "**/name/**" patterns to the literal segment "name".
func literalsOf(patterns []string) []string {
	var out []string
	for _, pat := range patterns {
		seg := strings.Trim(pat, "*/")
		seg = strings.Trim(seg, "/")
		if seg != "" && !strings.ContainsAny(seg, "*?[") {
			out = append(out, seg)
		}
	}
	return out
}

func excluded(p string, literals []string) bool {
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		for _, lit := range literals {
			if part == lit {
				return true
			}
		}
	}
	return false
}

func isHidden(p string) bool {
	return strings.HasPrefix(filepath.Base(p), ".")
}

func IsBinary(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 8192)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if n == 0 {
		// Empty file: scannable, never binary.
		return false, nil
	}
	for _, b := range buf[:n] {
		if b == 0 {
			return true, nil
		}
	}
	return false, nil
}

// ParseSize parses "5MB", "512KB", "1GB", or plain bytes.
func ParseSize(s string) (int64, error) {
	up := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(up, suf.s) {
			mult = suf.m
			up = strings.TrimSpace(strings.TrimSuffix(up, suf.s))
			break
		}
	}
	n, err := strconv.ParseInt(up, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * mult, nil
}
