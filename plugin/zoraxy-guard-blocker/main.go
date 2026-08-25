// Zoraxy Guard Blocker
//
// A Zoraxy Router plugin that blocks individual request paths with HTTP 403
// on a per-domain basis. Domains and paths are grouped by admin-defined
// Tags (this plugin's own tags — independent of Zoraxy's Proxy-Rule tags,
// see EnableTag in service.go). Entries are maintained manually in the
// plugin's Web UI, or imported in bulk from a Zoraxy Guard "Sperren"-Export.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	plugin "github.com/PaulG67/zoraxy-guard-blocker/mod/zoraxy_plugin"
)

const (
	pluginID    = "li.gehring.zoraxy-guard-blocker"
	uiPath      = "/ui"
	sniffPath   = "/d_sniff"
	capturePath = "/d_capture"
)

func spec() *plugin.IntroSpect {
	return &plugin.IntroSpect{
		ID:            pluginID,
		Name:          "Zoraxy Guard Blocker",
		Author:        "PaulG67",
		AuthorContact: "https://github.com/PaulG67",
		Description:   "Sperrt einzelne Pfade pro Domain mit HTTP 403, gruppiert über eigene Tags. Manuelle Pflege oder Import aus Zoraxy Guard.",
		URL:           "https://github.com/PaulG67/zoraxy-guard/tree/main/plugin/zoraxy-guard-blocker",
		Type:          plugin.PluginType_Router,
		VersionMajor:  1,
		VersionMinor:  0,
		VersionPatch:  0,

		DynamicCaptureSniff:   sniffPath,
		DynamicCaptureIngress: capturePath,
		UIPath:                uiPath,
		// Ask Zoraxy for an API key so the Domains page can offer a picker of
		// configured HTTP Proxy hostnames (POST /plugin/api/proxy/list).
		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{
			{
				Method:   "POST",
				Endpoint: "/plugin/api/proxy/list",
				Reason:   "Domains-Auswahl: HTTP-Proxy-Hostnamen aus Zoraxy laden",
			},
		},
	}
}

func dataFilePath() string {
	if v := os.Getenv("ZGB_DATA_FILE"); v != "" {
		return v
	}
	return filepath.Join(".", "data", "zoraxy-guard-blocker.json")
}

func main() {
	cfg, err := plugin.ServeAndRecvSpec(spec())
	if err != nil {
		log.Fatal("configuration error: ", err)
	}

	store, err := NewStore(dataFilePath())
	if err != nil {
		log.Fatal("store error: ", err)
	}

	svc := NewService(cfg, store)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("Zoraxy Guard Blocker listening on %s (data file: %s)", server.Addr, dataFilePath())
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
