package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/gatehouse/gatehouse/internal/enrich"
	"github.com/gatehouse/gatehouse/internal/evidence"
	"github.com/gatehouse/gatehouse/internal/store"
	"github.com/gatehouse/gatehouse/internal/ui"
)

// cmdServe starts the local web UI / API (plan §11). It binds to 127.0.0.1
// only; exposing it on other interfaces is deliberately left to a future flag
// guarded by an access token. The HTML UI is server-side rendered with htmx
// (served locally) and lives in internal/ui; this command adds the JSON API,
// a health check, and the localhost/Host-header guard around everything.
func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:7420", "listen address (localhost only by default)")
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	pluginsDir := fs.String("plugins", "", "additional plugin manifest directory for UI-triggered scans")
	noBuiltin := fs.Bool("no-builtin-plugins", false, "use only --plugins manifests for UI-triggered scans")
	hostExec := fs.Bool("unsafe-host-exec", false, "DEV ONLY: run UI-triggered scans on the host with no sandbox")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		return exitError
	}
	defer st.Close()

	uiServer, err := ui.New(st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init ui:", err)
		return exitError
	}
	keyID := "(not yet generated)"
	if k, err := evidence.LoadOrCreateKey(defaultKeyPath()); err == nil {
		keyID = k.KeyID()
	}
	uiServer.SetMeta(ui.Settings{
		BindAddr:   *addr,
		DBPath:     *dbPath,
		MirrorPath: defaultMirrorPath(),
		KeyID:      keyID,
		RetainPer:  50,
	})

	// Enable UI-triggered scans if a runtime is available. The runtime is
	// created once and reused; policy/config/waivers are resolved per scan.
	if rt := serveRuntime(*hostExec); rt != nil {
		defer rt.Close()
		plugs := loadServePlugins(*noBuiltin, *pluginsDir)
		mirror, _ := enrich.Load(defaultMirrorPath())
		audit, _ := evidence.OpenAuditLog(defaultAuditPath())
		fmt.Printf("scanning enabled via %s\n", rt.Name())

		uiServer.SetRunner(func(runID, repoPath, ref, _ string, progress func(string)) error {
			return runServeScan(st, rt, plugs, mirror, audit, runID, repoPath, progress)
		})
	} else {
		fmt.Println("scanning disabled (no container runtime; pass --unsafe-host-exec for a dev fallback)")
	}

	mux := http.NewServeMux()
	uiServer.Routes(mux)
	mux.HandleFunc("GET /api/runs", runsAPIHandler(st))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Addr: *addr, Handler: localhostOnly(mux)}
	fmt.Printf("gatehouse serving on http://%s\n", *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return exitError
	}
	return exitPass
}

// localhostOnly rejects requests whose Host header is not a loopback address,
// a basic DNS-rebinding guard (plan §11). A full implementation also checks
// Origin and issues CSRF tokens.
func localhostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch host {
		case "127.0.0.1", "localhost", "::1", "[::1]":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "forbidden: non-localhost Host header", http.StatusForbidden)
		}
	})
}

func runsAPIHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		runs, err := st.RecentRuns(50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(runs)
	}
}
