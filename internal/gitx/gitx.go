// Package gitx snapshots a repository into an isolated directory for scanning
// and computes the changed-file set for diff-scoped runs. The user's working
// copy is never modified: snapshots are copies or git-archive extractions.
package gitx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Snapshot is the result of materialising code for a run.
type Snapshot struct {
	// Dir is the directory holding the read-only source to mount at /src.
	Dir string
	// TreeHash identifies the snapshot's content; part of the run's evidence.
	TreeHash string
	// Changed lists repo-relative paths that differ from BaseRef (diff mode only).
	Changed []string
}

// IsRepo reports whether dir is inside a git work tree.
func IsRepo(dir string) bool {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	return cmd.Run() == nil
}

// HooksDir returns the absolute path to the repo's hooks directory, honouring a
// configured core.hooksPath.
func HooksDir(dir string) (string, error) {
	out, err := git(dir, "rev-parse", "--path-format=absolute", "--git-path", "hooks")
	if err != nil {
		// Older gits don't support --path-format; fall back to the git dir.
		gd, err2 := git(dir, "rev-parse", "--absolute-git-dir")
		if err2 != nil {
			return "", err
		}
		return filepath.Join(strings.TrimSpace(gd), "hooks"), nil
	}
	return strings.TrimSpace(out), nil
}

// TopLevel returns the absolute path to the repo's working-tree root.
func TopLevel(dir string) (string, error) {
	out, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// SnapshotWorkingTree copies tracked and untracked-but-not-ignored files from
// repoDir into destDir, preserving the uncommitted working state while never
// touching the original. If repoDir is not a git repo it falls back to a plain
// recursive copy.
func SnapshotWorkingTree(repoDir, destDir string) (*Snapshot, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}

	var files []string
	if IsRepo(repoDir) {
		out, err := git(repoDir, "ls-files", "-co", "--exclude-standard")
		if err != nil {
			return nil, fmt.Errorf("list files: %w", err)
		}
		files = splitLines(out)
	} else {
		var err error
		files, err = walkAll(repoDir)
		if err != nil {
			return nil, err
		}
	}

	h := sha256.New()
	sort.Strings(files)
	for _, rel := range files {
		src := filepath.Join(repoDir, rel)
		info, err := os.Lstat(src)
		if err != nil || !info.Mode().IsRegular() {
			continue // skip symlinks, dangling entries
		}
		dst := filepath.Join(destDir, rel)
		if err := copyFile(src, dst); err != nil {
			return nil, err
		}
		// Fold path + content into the tree hash.
		h.Write([]byte(rel))
		h.Write([]byte{0})
		if err := hashFile(h, src); err != nil {
			return nil, err
		}
	}

	return &Snapshot{Dir: destDir, TreeHash: hex.EncodeToString(h.Sum(nil))}, nil
}

// ChangedFiles returns the repo-relative paths changed between baseRef and the
// working tree. Used to scope scanners to the diff in pre-push mode.
func ChangedFiles(repoDir, baseRef string) ([]string, error) {
	// Three-dot against the merge base is what reviewers see as "the diff".
	out, err := git(repoDir, "diff", "--name-only", baseRef+"...", "--")
	if err != nil {
		// Fall back to a two-dot diff if there's no common ancestor.
		out, err = git(repoDir, "diff", "--name-only", baseRef, "--")
		if err != nil {
			return nil, fmt.Errorf("diff against %s: %w", baseRef, err)
		}
	}
	return splitLines(out), nil
}

// HeadCommit returns the full SHA of HEAD.
func HeadCommit(dir string) (string, error) {
	out, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// WriteNote attaches content to a commit under refs/notes/<noteRef>, replacing
// any existing note. Used for the signed pre-push attestation (plan §10/§12) so
// CI can verify a local scan really ran.
func WriteNote(dir, noteRef, commit, content string) error {
	_, err := git(dir, "notes", "--ref="+noteRef, "add", "-f", "-m", content, commit)
	return err
}

// ReadNote returns the note content attached to a commit under the given ref,
// or an error if there is none.
func ReadNote(dir, noteRef, commit string) (string, error) {
	out, err := git(dir, "notes", "--ref="+noteRef, "show", commit)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(out, "\n"), nil
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, errb.String())
	}
	return out.String(), nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func walkAll(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	return out, err
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func hashFile(h io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(h, f)
	return err
}
