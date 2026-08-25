package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	plugin "github.com/PaulG67/zoraxy-guard-blocker/mod/zoraxy_plugin"
)

// EnableTag is the single Zoraxy-side tag admins attach to an HTTP Proxy
// Rule (and enable this plugin for) so that traffic for that domain reaches
// this plugin at all. Which paths are actually blocked for that domain is
// then decided entirely by this plugin's own tags (see store.go / README).
const EnableTag = "zoraxy-guard-blocker"

const maxImportBody = 2 << 20 // 2 MiB

//go:embed www/ui.tmpl
var uiTemplateSource string

//go:embed www/forbidden.tmpl
var forbiddenTemplateSource string

var uiTemplates = template.Must(template.New("ui").Parse(uiTemplateSource))
var forbiddenTemplate = template.Must(template.New("forbidden").Parse(forbiddenTemplateSource))

type Service struct {
	cfg      *plugin.ConfigureSpec
	store    *Store
	mux      *http.ServeMux
	captures *captureStore
}

func NewService(cfg *plugin.ConfigureSpec, store *Store) *Service {
	s := &Service{
		cfg:      cfg,
		store:    store,
		mux:      http.NewServeMux(),
		captures: newCaptureStore(),
	}
	s.registerRoutes()
	return s
}

func (s *Service) Handler() http.Handler { return s.mux }

func (s *Service) registerRoutes() {
	s.mux.HandleFunc(uiPath+"/", s.handleUIRoot)
	s.mux.HandleFunc(uiPath+"/rules", s.handleRules)
	s.mux.HandleFunc(uiPath+"/domains", s.handleDomains)
	s.mux.HandleFunc(uiPath+"/import", s.handleImport)
	s.mux.HandleFunc(sniffPath+"/", s.handleSniff)
	s.mux.HandleFunc(capturePath+"/", s.handleCapture)
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
}

// ---------------------------------------------------------------------------
// Shared page rendering
// ---------------------------------------------------------------------------

type layoutData struct {
	Title     string
	Active    string
	UIPath    string
	CSRFToken string
	Flash     string
	FlashKind string
	Content   template.HTML
}

func (s *Service) render(w http.ResponseWriter, r *http.Request, active, title, contentTemplate string, data any, flash, flashKind string) {
	var body bytes.Buffer
	if err := uiTemplates.ExecuteTemplate(&body, contentTemplate, data); err != nil {
		http.Error(w, "Template-Fehler: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ld := layoutData{
		Title:     title,
		Active:    active,
		UIPath:    uiPath,
		CSRFToken: r.Header.Get("X-Zoraxy-Csrf"),
		Flash:     flash,
		FlashKind: flashKind,
		Content:   template.HTML(body.String()),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := uiTemplates.ExecuteTemplate(w, "layout", ld); err != nil {
		log.Printf("layout render error: %v", err)
	}
}

func (s *Service) handleUIRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != uiPath+"/" && r.URL.Path != uiPath {
		http.NotFound(w, r)
		return
	}
	type tagSummary struct {
		Name        string
		DomainCount int
		RuleCount   int
	}
	type recentHit struct {
		Path    string
		Tag     string
		Hits    int64
		LastHit string
	}

	rules := s.store.Rules()
	domains := s.store.DomainTags()
	tags := s.store.Tags()

	domainsByTag := map[string]int{}
	for _, d := range domains {
		for _, t := range d.Tags {
			domainsByTag[t]++
		}
	}
	rulesByTag := map[string]int{}
	for _, rl := range rules {
		if rl.Enabled {
			rulesByTag[rl.Tag]++
		}
	}
	summaries := make([]tagSummary, 0, len(tags))
	for _, t := range tags {
		summaries = append(summaries, tagSummary{Name: t.Name, DomainCount: domainsByTag[t.Name], RuleCount: rulesByTag[t.Name]})
	}

	hit := make([]PathRule, 0)
	for _, rl := range rules {
		if rl.Hits > 0 {
			hit = append(hit, rl)
		}
	}
	sort.Slice(hit, func(i, j int) bool { return hit[i].LastHitAt > hit[j].LastHitAt })
	if len(hit) > 15 {
		hit = hit[:15]
	}
	recent := make([]recentHit, 0, len(hit))
	for _, rl := range hit {
		last := "—"
		if rl.LastHitAt > 0 {
			last = time.Unix(rl.LastHitAt, 0).Format("2006-01-02 15:04:05")
		}
		recent = append(recent, recentHit{Path: rl.Path, Tag: rl.Tag, Hits: rl.Hits, LastHit: last})
	}

	data := struct {
		UIPath       string
		EnableTag    string
		Tags         []Tag
		TagSummaries []tagSummary
		RecentHits   []recentHit
	}{uiPath, EnableTag, tags, summaries, recent}
	s.render(w, r, "dashboard", "Übersicht", "dashboard", data, flashFromQuery(r), flashKindFromQuery(r))
}

func flashFromQuery(r *http.Request) string { return r.URL.Query().Get("flash") }
func flashKindFromQuery(r *http.Request) string {
	if k := r.URL.Query().Get("flash_kind"); k != "" {
		return k
	}
	return "ok"
}

func redirectWithFlash(w http.ResponseWriter, r *http.Request, target, msg, kind string) {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	http.Redirect(w, r, fmt.Sprintf("%s%sflash=%s&flash_kind=%s", target, sep, template.URLQueryEscaper(msg), kind), http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Rules page
// ---------------------------------------------------------------------------

func (s *Service) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleRulesPost(w, r)
		return
	}
	data := struct {
		UIPath    string
		CSRFToken string
		Tags      []Tag
		Rules     []PathRule
	}{uiPath, r.Header.Get("X-Zoraxy-Csrf"), s.store.Tags(), s.store.Rules()}
	s.render(w, r, "rules", "Pfad-Regeln", "rules", data, flashFromQuery(r), flashKindFromQuery(r))
}

func (s *Service) handleRulesPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	switch action {
	case "add":
		rule := PathRule{
			Path:      r.FormValue("path"),
			MatchType: MatchType(r.FormValue("match_type")),
			Tag:       r.FormValue("tag"),
			Note:      r.FormValue("note"),
			Enabled:   true,
			Source:    "manual",
		}
		if rule.MatchType == "" {
			rule.MatchType = MatchExact
		}
		if _, err := s.store.AddRule(rule); err != nil {
			redirectWithFlash(w, r, uiPath+"/rules", err.Error(), "error")
			return
		}
		redirectWithFlash(w, r, uiPath+"/rules", "Regel hinzugefügt.", "ok")
	case "toggle":
		id := r.FormValue("id")
		err := s.store.UpdateRule(id, func(pr *PathRule) error {
			pr.Enabled = !pr.Enabled
			return nil
		})
		if err != nil {
			redirectWithFlash(w, r, uiPath+"/rules", err.Error(), "error")
			return
		}
		redirectWithFlash(w, r, uiPath+"/rules", "Regel aktualisiert.", "ok")
	case "delete":
		if err := s.store.DeleteRule(r.FormValue("id")); err != nil {
			redirectWithFlash(w, r, uiPath+"/rules", err.Error(), "error")
			return
		}
		redirectWithFlash(w, r, uiPath+"/rules", "Regel gelöscht.", "ok")
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Domains page
// ---------------------------------------------------------------------------

func (s *Service) handleDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleDomainsPost(w, r)
		return
	}
	data := struct {
		UIPath    string
		CSRFToken string
		Tags      []Tag
		Domains   []DomainTags
	}{uiPath, r.Header.Get("X-Zoraxy-Csrf"), s.store.Tags(), s.store.DomainTags()}
	s.render(w, r, "domains", "Domains", "domains", data, flashFromQuery(r), flashKindFromQuery(r))
}

func (s *Service) handleDomainsPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	switch r.FormValue("action") {
	case "set":
		tags := strings.Split(r.FormValue("tags"), ",")
		if err := s.store.SetDomainTags(r.FormValue("domain"), tags); err != nil {
			redirectWithFlash(w, r, uiPath+"/domains", err.Error(), "error")
			return
		}
		redirectWithFlash(w, r, uiPath+"/domains", "Domain gespeichert.", "ok")
	case "delete":
		if err := s.store.DeleteDomain(r.FormValue("domain")); err != nil {
			redirectWithFlash(w, r, uiPath+"/domains", err.Error(), "error")
			return
		}
		redirectWithFlash(w, r, uiPath+"/domains", "Domain entfernt.", "ok")
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Import flow: paste/upload Zoraxy Guard export -> assign tags -> apply
// ---------------------------------------------------------------------------

func (s *Service) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		data := struct {
			UIPath    string
			CSRFToken string
		}{uiPath, r.Header.Get("X-Zoraxy-Csrf")}
		s.render(w, r, "import", "Import", "import_form", data, flashFromQuery(r), flashKindFromQuery(r))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxImportBody)
	step := r.FormValue("step")
	if step == "" {
		if err := r.ParseMultipartForm(maxImportBody); err != nil {
			// might just be a normal form without file
			_ = r.ParseForm()
		}
		step = r.FormValue("step")
	}

	switch step {
	case "preview":
		raw, err := readImportPayload(r)
		if err != nil {
			redirectWithFlash(w, r, uiPath+"/import", err.Error(), "error")
			return
		}
		rows, skipped, err := parseImportPayload(raw)
		if err != nil {
			redirectWithFlash(w, r, uiPath+"/import", err.Error(), "error")
			return
		}
		if len(rows) == 0 {
			redirectWithFlash(w, r, uiPath+"/import", "Keine gültigen Einträge in der Datei gefunden.", "error")
			return
		}
		data := struct {
			UIPath       string
			CSRFToken    string
			Tags         []Tag
			Rows         []importRow
			SkippedCount int
		}{uiPath, r.Header.Get("X-Zoraxy-Csrf"), s.store.Tags(), rows, skipped}
		s.render(w, r, "import", "Import — Tags zuweisen", "import_preview", data, "", "")
	case "apply":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		domains := r.Form["domain"]
		paths := r.Form["path"]
		tags := r.Form["tag"]
		matches := r.Form["match_type"]
		if len(domains) != len(paths) || len(domains) != len(tags) || len(domains) != len(matches) {
			redirectWithFlash(w, r, uiPath+"/import", "Formular unvollständig — bitte erneut importieren.", "error")
			return
		}
		added := 0
		for i := range domains {
			domain := strings.TrimSpace(domains[i])
			p := strings.TrimSpace(paths[i])
			tag := strings.TrimSpace(tags[i])
			mt := MatchType(strings.TrimSpace(matches[i]))
			if domain == "" || p == "" || tag == "" {
				continue
			}
			if mt == "" {
				mt = MatchExact
			}
			if _, err := s.store.AddRule(PathRule{Path: p, MatchType: mt, Tag: tag, Source: "import", Enabled: true}); err != nil {
				continue
			}
			if err := s.store.AddDomainTags(domain, []string{tag}); err != nil {
				continue
			}
			added++
		}
		redirectWithFlash(w, r, uiPath+"/rules", fmt.Sprintf("%d Regel(n) aus Import übernommen.", added), "ok")
	default:
		http.Error(w, "unknown step", http.StatusBadRequest)
	}
}

func readImportPayload(r *http.Request) ([]byte, error) {
	if f, _, err := r.FormFile("file"); err == nil {
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxImportBody))
		if err != nil {
			return nil, fmt.Errorf("Datei konnte nicht gelesen werden: %w", err)
		}
		if len(data) > 0 {
			return data, nil
		}
	}
	raw := strings.TrimSpace(r.FormValue("raw_json"))
	if raw == "" {
		return nil, fmt.Errorf("bitte eine Datei hochladen oder JSON einfügen")
	}
	return []byte(raw), nil
}

// ---------------------------------------------------------------------------
// Dynamic capture (the actual blocking logic on live traffic)
// ---------------------------------------------------------------------------

type sniffRequest struct {
	Hostname   string `json:"hostname"`
	RequestURI string `json:"request_uri"`
	RemoteAddr string `json:"remote_addr"`
}

func (s *Service) handleSniff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req sniffRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid sniff payload", http.StatusBadRequest)
		return
	}
	rule, blocked := s.store.MatchBlocked(req.Hostname, req.RequestURI)
	if !blocked {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("SKIP"))
		return
	}
	s.store.RecordHit(rule.ID)
	s.captures.put(r.Header.Get("X-Zoraxy-RequestID"), rule)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Service) handleCapture(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.captures.take(r.Header.Get("X-Zoraxy-RequestID"))
	if !ok {
		http.Error(w, "Anfrage abgelaufen — bitte erneut versuchen.", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = forbiddenTemplate.Execute(w, struct{ Tag string }{rule.Tag})
}
