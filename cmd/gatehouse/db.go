package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// cmdDB implements "gatehouse db update" (plan §13): refresh the locally
// mirrored OSV/EPSS/KEV/CVSS feeds. Online fetching is intentionally not wired
// here (Gatehouse is offline-first); the supported path is `--from <dir>`,
// which loads the feeds from a USB/drive copy for air-gapped machines. The
// mirror lives under ~/.gatehouse/mirror and is read by every scan.
func cmdDB(args []string) int {
	if len(args) == 0 || args[0] != "update" {
		fmt.Fprintln(os.Stderr, "usage: gatehouse db update --from <dir>")
		return exitError
	}
	fs := flag.NewFlagSet("db update", flag.ExitOnError)
	from := fs.String("from", "", "directory holding cvss.json, epss.csv, kev.json to import")
	fs.Parse(args[1:])

	dst := defaultMirrorPath()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}

	if *from == "" {
		fmt.Fprintln(os.Stderr, "online feed download is not available in this build; use --from <dir> to import a mirror")
		fmt.Printf("mirror directory: %s\n", dst)
		return exitError
	}

	var copied int
	for _, name := range []string{"cvss.json", "epss.csv", "kev.json"} {
		src := filepath.Join(*from, name)
		if _, err := os.Stat(src); err != nil {
			continue // feed not present in the source; skip
		}
		if err := copyFileTo(src, filepath.Join(dst, name)); err != nil {
			fmt.Fprintf(os.Stderr, "copy %s: %v\n", name, err)
			return exitError
		}
		copied++
		fmt.Printf("✓ imported %s\n", name)
	}
	if copied == 0 {
		fmt.Fprintf(os.Stderr, "no feed files (cvss.json/epss.csv/kev.json) found in %s\n", *from)
		return exitError
	}
	fmt.Printf("mirror updated at %s\n", dst)
	return exitPass
}

func defaultMirrorPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "gatehouse-mirror"
	}
	return filepath.Join(home, ".gatehouse", "mirror")
}

func copyFileTo(src, dst string) error {
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
