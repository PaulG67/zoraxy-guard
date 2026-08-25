package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	plugin "github.com/PaulG67/zoraxy-guard-blocker/mod/zoraxy_plugin"
)

// proxyEndpointLite is the subset of Zoraxy's ProxyEndpoint JSON we need to
// build the Domains picker. Field names match Go's default JSON encoding
// (no struct tags on the upstream type).
type proxyEndpointLite struct {
	RootOrMatchingDomain string   `json:"RootOrMatchingDomain"`
	MatchingDomainAlias  []string `json:"MatchingDomainAlias"`
	Disabled             bool     `json:"Disabled"`
}

// listZoraxyProxyHosts asks Zoraxy for every HTTP Proxy Rule hostname
// (including aliases). Requires PermittedAPIEndpoints to include
// POST /plugin/api/proxy/list and a non-empty API key in ConfigureSpec.
func listZoraxyProxyHosts(cfg *plugin.ConfigureSpec) ([]string, error) {
	if cfg == nil {
		return nil, fmt.Errorf("keine Runtime-Config")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("kein API-Key — Plugin in Zoraxy neu starten, damit der Schlüssel erzeugt wird")
	}
	port := cfg.ZoraxyPort
	if port <= 0 {
		port = 8000
	}

	apiURL := fmt.Sprintf("http://127.0.0.1:%d/plugin/api/proxy/list", port)
	form := url.Values{"type": {"host"}}
	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Zoraxy-API nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Zoraxy-API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var endpoints []proxyEndpointLite
	if err := json.Unmarshal(body, &endpoints); err != nil {
		return nil, fmt.Errorf("ungültige API-Antwort: %w", err)
	}

	seen := map[string]bool{}
	out := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.Disabled {
			continue
		}
		for _, raw := range append([]string{ep.RootOrMatchingDomain}, ep.MatchingDomainAlias...) {
			h := normalizeDomain(raw)
			if h == "" || h == "/" || seen[h] {
				continue
			}
			// Skip catch-all / internal placeholder hosts.
			if strings.HasSuffix(h, ".internal") {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out, nil
}
