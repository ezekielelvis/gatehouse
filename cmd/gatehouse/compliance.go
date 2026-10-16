package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/gatehouse/gatehouse/internal/standards"
	"github.com/gatehouse/gatehouse/internal/store"
	standardsdata "github.com/gatehouse/gatehouse/standards"
)

// cmdCompliance maps a stored run onto a recognised standard and prints a
// control-by-control report (plan §7):
//
//	gatehouse compliance <run-id> --standard owasp-top10
func cmdCompliance(args []string) int {
	fs := flag.NewFlagSet("compliance", flag.ExitOnError)
	std := fs.String("standard", "owasp-top10", "standard to map against (owasp-top10, cwe-top25)")
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")

	runID := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		runID = args[0]
		args = args[1:]
	}
	fs.Parse(args)
	if runID == "" {
		names, _ := standardsdata.List()
		fmt.Fprintf(os.Stderr, "usage: gatehouse compliance <run-id> --standard <name>\navailable standards: %v\n", names)
		return exitError
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		return exitError
	}
	defer st.Close()

	run, _, _, err := st.GetRun(runID)
	if err != nil || run == nil {
		fmt.Fprintf(os.Stderr, "no such run: %s\n", runID)
		return exitError
	}

	standard, err := standardsdata.Load(*std)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}

	rep := standards.Evaluate(standard, *run)
	printCompliance(rep)
	return exitPass
}

func printCompliance(rep standards.Report) {
	symbol := map[standards.Status]string{
		standards.StatusMet:           "✓ met",
		standards.StatusNotMet:        "✗ NOT MET",
		standards.StatusManual:        "– manual",
		standards.StatusNotApplicable: "· n/a",
	}
	fmt.Printf("\n%s %s — control coverage\n\n", rep.Title, rep.Version)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, cr := range rep.Results {
		detail := ""
		if cr.Status == standards.StatusNotMet {
			if len(cr.Findings) > 0 {
				detail = fmt.Sprintf("(%d finding(s))", len(cr.Findings))
			} else {
				detail = "(required analysis did not complete)"
			}
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", cr.Control.ID, symbol[cr.Status], cr.Control.Title, detail)
	}
	tw.Flush()

	c := rep.Counts()
	fmt.Printf("\nsummary: %d met · %d not met · %d manual\n",
		c[standards.StatusMet], c[standards.StatusNotMet], c[standards.StatusManual])
	fmt.Println("note: 'manual' controls require human attestation; Gatehouse does not auto-pass them.")
}
