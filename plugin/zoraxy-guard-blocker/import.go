package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// importEntry mirrors the "zoraxy-guard-blocker/import-v1" export format
// produced by Zoraxy Guard's History → "Sperren"-Export.
type importEntry struct {
	Domain string  `json:"domain"`
	Path   string  `json:"path"`
	Method string  `json:"method,omitempty"`
	Status *int    `json:"status,omitempty"`
	Note   string  `json:"note,omitempty"`
	TS     float64 `json:"ts,omitempty"`
}

type importFile struct {
	Format  string        `json:"format,omitempty"`
	Source  string        `json:"source,omitempty"`
	Entries []importEntry `json:"entries"`
}

// importRow is a normalized, pre-filled row shown on the "assign tags"
// preview screen.
type importRow struct {
	Domain         string
	Path           string
	Status         string
	Note           string
	SuggestedTag   string
	SuggestedMatch MatchType
}

func parseImportPayload(raw []byte) ([]importRow, int, error) {
	var f importFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, 0, fmt.Errorf("ungültiges JSON: %w", err)
	}
	rows := make([]importRow, 0, len(f.Entries))
	skipped := 0
	for _, e := range f.Entries {
		domain := normalizeDomain(e.Domain)
		p := strings.TrimSpace(e.Path)
		if domain == "" || p == "" || !strings.HasPrefix(p, "/") {
			skipped++
			continue
		}
		status := ""
		if e.Status != nil {
			status = fmt.Sprintf("%d", *e.Status)
		}
		rows = append(rows, importRow{
			Domain:         domain,
			Path:           p,
			Status:         status,
			Note:           e.Note,
			SuggestedTag:   suggestTag(p),
			SuggestedMatch: MatchExact,
		})
	}
	return rows, skipped, nil
}

// suggestTag offers a sensible default tag name based on the path, purely
// as a convenience the admin can overwrite before applying.
func suggestTag(p string) string {
	low := strings.ToLower(p)
	switch {
	case strings.Contains(low, ".git"):
		return "git-exposure"
	case strings.Contains(low, ".env"):
		return "dotfiles"
	case strings.Contains(low, "wp-config") || strings.Contains(low, "wp-admin") || strings.Contains(low, "wp-login"):
		return "wordpress"
	case strings.Contains(low, "id_rsa") || strings.Contains(low, ".aws") || strings.Contains(low, ".ssh"):
		return "secrets"
	default:
		return "scanner-paths"
	}
}
