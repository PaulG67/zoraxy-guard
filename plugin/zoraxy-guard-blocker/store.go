package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// MatchType describes how PathRule.Path is compared against an incoming
// request path.
type MatchType string

const (
	MatchExact    MatchType = "exact"
	MatchPrefix   MatchType = "prefix"
	MatchWildcard MatchType = "wildcard"
)

const maxRules = 5000
const maxDomains = 2000

// Tag is a small label used to group PathRules and to link them to the
// domains they should apply to. Tags are entirely internal to this plugin —
// Zoraxy's own "Tag" concept on HTTP Proxy Rules is only used to decide
// whether traffic reaches this plugin at all (see README / dashboard).
type Tag struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
}

// DomainTags assigns one or more of this plugin's Tags to a domain
// (HTTP Proxy Rule hostname).
type DomainTags struct {
	Domain string   `json:"domain"`
	Tags   []string `json:"tags"`
}

// PathRule is a single "block this path if the domain carries this tag"
// rule.
type PathRule struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	MatchType MatchType `json:"match_type"`
	Tag       string    `json:"tag"`
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note,omitempty"`
	Source    string    `json:"source,omitempty"` // "manual" | "import"
	CreatedAt int64     `json:"created_at"`
	Hits      int64     `json:"hits"`
	LastHitAt int64     `json:"last_hit_at,omitempty"`
}

type dataFile struct {
	Tags       []Tag        `json:"tags"`
	DomainTags []DomainTags `json:"domain_tags"`
	Rules      []PathRule   `json:"rules"`
	HitLog     []HitEvent   `json:"hit_log,omitempty"`
}

// HitEvent is one blocked request, kept for a rolling window so the stats
// page can chart activity over time (not just lifetime counters on PathRule).
type HitEvent struct {
	TS     int64  `json:"ts"`
	RuleID string `json:"rule_id"`
	Path   string `json:"path"`
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

const (
	maxHitEvents    = 20000
	hitRetentionSec = 14 * 24 * 60 * 60 // 14 days
)

// Store is the JSON-file backed, mutex-protected persistence layer for this
// plugin. It intentionally stays a single small file — no database
// dependency — per the initial scope of this plugin.
type Store struct {
	path string
	mu   sync.RWMutex
	data dataFile
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.data = dataFile{Tags: []Tag{}, DomainTags: []DomainTags{}, Rules: []PathRule{}, HitLog: []HitEvent{}}
		return nil
	}
	if err != nil {
		return err
	}
	var df dataFile
	if err := json.Unmarshal(raw, &df); err != nil {
		return fmt.Errorf("data file %s is corrupt: %w", s.path, err)
	}
	if df.Tags == nil {
		df.Tags = []Tag{}
	}
	if df.DomainTags == nil {
		df.DomainTags = []DomainTags{}
	}
	if df.Rules == nil {
		df.Rules = []PathRule{}
	}
	if df.HitLog == nil {
		df.HitLog = []HitEvent{}
	}
	s.data = df
	return nil
}

// Path is the data file this store persists to.
func (s *Store) Path() string { return s.path }

// WriteCheck rewrites the data file from the current in-memory state. It
// exists so the UI self-test can prove the file is genuinely writable
// instead of only reporting its path.
func (s *Store) WriteCheck() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".zgb-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

func normalizeDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	return strings.TrimSuffix(v, ".")
}

func normalizeTag(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// ---- Tags ----

func (s *Store) Tags() []Tag {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tag, len(s.data.Tags))
	copy(out, s.data.Tags)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UpsertTag creates the tag if it does not exist yet (or updates its note).
func (s *Store) UpsertTag(name, note string) error {
	name = normalizeTag(name)
	if name == "" {
		return fmt.Errorf("tag name darf nicht leer sein")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Tags {
		if s.data.Tags[i].Name == name {
			if note != "" {
				s.data.Tags[i].Note = note
			}
			return s.saveLocked()
		}
	}
	s.data.Tags = append(s.data.Tags, Tag{Name: name, Note: note})
	return s.saveLocked()
}

func (s *Store) DeleteTag(name string) error {
	name = normalizeTag(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.data.Tags[:0]
	for _, t := range s.data.Tags {
		if t.Name != name {
			kept = append(kept, t)
		}
	}
	s.data.Tags = kept
	return s.saveLocked()
}

// ensureTagLocked makes sure the tag exists in the tag list (used whenever a
// rule or domain references a not-yet-known tag).
func (s *Store) ensureTagLocked(name string) {
	name = normalizeTag(name)
	if name == "" {
		return
	}
	for _, t := range s.data.Tags {
		if t.Name == name {
			return
		}
	}
	s.data.Tags = append(s.data.Tags, Tag{Name: name})
}

// ---- Domain <-> Tags ----

func (s *Store) DomainTags() []DomainTags {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DomainTags, len(s.data.DomainTags))
	copy(out, s.data.DomainTags)
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// SetDomainTags replaces the tag set for a domain outright (used by the
// manual "Domains" form).
func (s *Store) SetDomainTags(domain string, tags []string) error {
	domain = normalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("domain darf nicht leer sein")
	}
	clean := cleanTagList(tags)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.DomainTags) >= maxDomains {
		found := false
		for _, d := range s.data.DomainTags {
			if d.Domain == domain {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("maximal %d Domains erlaubt", maxDomains)
		}
	}
	for _, t := range clean {
		s.ensureTagLocked(t)
	}
	for i := range s.data.DomainTags {
		if s.data.DomainTags[i].Domain == domain {
			s.data.DomainTags[i].Tags = clean
			return s.saveLocked()
		}
	}
	s.data.DomainTags = append(s.data.DomainTags, DomainTags{Domain: domain, Tags: clean})
	return s.saveLocked()
}

// AddDomainTags merges (adds, without removing) tags into a domain's set —
// used by the import flow so re-importing is safe/idempotent.
func (s *Store) AddDomainTags(domain string, tags []string) error {
	domain = normalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("domain darf nicht leer sein")
	}
	add := cleanTagList(tags)
	if len(add) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range add {
		s.ensureTagLocked(t)
	}
	for i := range s.data.DomainTags {
		if s.data.DomainTags[i].Domain == domain {
			s.data.DomainTags[i].Tags = mergeTagLists(s.data.DomainTags[i].Tags, add)
			return s.saveLocked()
		}
	}
	s.data.DomainTags = append(s.data.DomainTags, DomainTags{Domain: domain, Tags: add})
	return s.saveLocked()
}

func (s *Store) DeleteDomain(domain string) error {
	domain = normalizeDomain(domain)
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.data.DomainTags[:0]
	for _, d := range s.data.DomainTags {
		if d.Domain != domain {
			kept = append(kept, d)
		}
	}
	s.data.DomainTags = kept
	return s.saveLocked()
}

func cleanTagList(tags []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range tags {
		t = normalizeTag(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func mergeTagLists(existing, add []string) []string {
	return cleanTagList(append(append([]string{}, existing...), add...))
}

// ---- Path rules ----

func (s *Store) Rules() []PathRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PathRule, len(s.data.Rules))
	copy(out, s.data.Rules)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tag != out[j].Tag {
			return out[i].Tag < out[j].Tag
		}
		return out[i].Path < out[j].Path
	})
	return out
}

var (
	// ErrDuplicateRule is returned by AddRule when an enabled-or-disabled rule
	// with the same path and match type already exists (tag may differ).
	ErrDuplicateRule = fmt.Errorf("Regel mit diesem Pfad und Match-Typ existiert bereits")
)

func validateRule(r *PathRule) error {
	r.Path = strings.TrimSpace(r.Path)
	r.Tag = normalizeTag(r.Tag)
	if r.Path == "" {
		return fmt.Errorf("Pfad darf nicht leer sein")
	}
	if !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("Pfad muss mit / beginnen")
	}
	if r.Tag == "" {
		return fmt.Errorf("Tag darf nicht leer sein")
	}
	switch r.MatchType {
	case MatchExact, MatchPrefix:
		// nothing further to validate
	case MatchWildcard:
		if _, err := path.Match(r.Path, "/"); err != nil {
			return fmt.Errorf("ungültiges Wildcard-Muster: %w", err)
		}
	default:
		return fmt.Errorf("unbekannter match_type %q", r.MatchType)
	}
	return nil
}

// AddRule creates a new path rule and returns it (with a generated ID).
// Rules that share the same path and match type as an existing entry are
// rejected with ErrDuplicateRule so imports and manual adds stay idempotent.
func (s *Store) AddRule(r PathRule) (PathRule, error) {
	if err := validateRule(&r); err != nil {
		return PathRule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Rules) >= maxRules {
		return PathRule{}, fmt.Errorf("maximal %d Regeln erlaubt", maxRules)
	}
	for _, existing := range s.data.Rules {
		if existing.Path == r.Path && existing.MatchType == r.MatchType {
			return PathRule{}, ErrDuplicateRule
		}
	}
	s.ensureTagLocked(r.Tag)
	r.ID = newID()
	r.CreatedAt = time.Now().Unix()
	if r.Source == "" {
		r.Source = "manual"
	}
	s.data.Rules = append(s.data.Rules, r)
	if err := s.saveLocked(); err != nil {
		return PathRule{}, err
	}
	return r, nil
}

func (s *Store) UpdateRule(id string, mut func(*PathRule) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Rules {
		if s.data.Rules[i].ID == id {
			updated := s.data.Rules[i]
			if err := mut(&updated); err != nil {
				return err
			}
			if err := validateRule(&updated); err != nil {
				return err
			}
			s.ensureTagLocked(updated.Tag)
			s.data.Rules[i] = updated
			return s.saveLocked()
		}
	}
	return fmt.Errorf("Regel %q nicht gefunden", id)
}

func (s *Store) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.data.Rules[:0]
	for _, r := range s.data.Rules {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	s.data.Rules = kept
	return s.saveLocked()
}

// RecordHit increments the hit counter for a rule and appends a timed event
// for the stats chart. Best-effort: errors are swallowed by the caller since
// this must never affect the block decision.
func (s *Store) RecordHit(id, domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	var path, tag string
	found := false
	for i := range s.data.Rules {
		if s.data.Rules[i].ID == id {
			s.data.Rules[i].Hits++
			s.data.Rules[i].LastHitAt = now
			path = s.data.Rules[i].Path
			tag = s.data.Rules[i].Tag
			found = true
			break
		}
	}
	if !found {
		return
	}
	s.data.HitLog = append(s.data.HitLog, HitEvent{
		TS:     now,
		RuleID: id,
		Path:   path,
		Tag:    tag,
		Domain: normalizeDomain(domain),
	})
	s.pruneHitLogLocked(now)
	_ = s.saveLocked()
}

func (s *Store) pruneHitLogLocked(now int64) {
	cutoff := now - hitRetentionSec
	kept := s.data.HitLog[:0]
	for _, h := range s.data.HitLog {
		if h.TS >= cutoff {
			kept = append(kept, h)
		}
	}
	s.data.HitLog = kept
	if len(s.data.HitLog) > maxHitEvents {
		s.data.HitLog = s.data.HitLog[len(s.data.HitLog)-maxHitEvents:]
	}
}

// HitStats summarises blocked requests for the stats page chart.
type HitStats struct {
	Window     string
	Buckets    []HitBucket
	Total      int64
	TopPaths   []HitRank
	TopTags    []HitRank
	TopDomains []HitRank
}

type HitBucket struct {
	Label string
	Count int64
}

type HitRank struct {
	Name  string
	Count int64
	Pct   int // 0–100 relative to the top entry, for the bar width
}

// Stats returns bucketed hit counts for window "24h", "7d", or "14d".
func (s *Store) Stats(window string) HitStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var bucketDur time.Duration
	var nBuckets int
	switch window {
	case "7d":
		bucketDur = 24 * time.Hour
		nBuckets = 7
	case "14d":
		bucketDur = 24 * time.Hour
		nBuckets = 14
	default:
		window = "24h"
		bucketDur = time.Hour
		nBuckets = 24
	}

	var bucketStart time.Time
	if bucketDur == time.Hour {
		bucketStart = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location()).
			Add(-time.Duration(nBuckets-1) * time.Hour)
	} else {
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		bucketStart = today.Add(-time.Duration(nBuckets-1) * 24 * time.Hour)
	}
	since := bucketStart

	buckets := make([]HitBucket, nBuckets)
	for i := 0; i < nBuckets; i++ {
		t := bucketStart.Add(time.Duration(i) * bucketDur)
		label := t.Format("15:04")
		if bucketDur >= 24*time.Hour {
			label = t.Format("02.01")
		}
		buckets[i] = HitBucket{Label: label}
	}

	pathCount := map[string]int64{}
	tagCount := map[string]int64{}
	domainCount := map[string]int64{}
	var total int64
	sinceUnix := since.Unix()

	for _, h := range s.data.HitLog {
		if h.TS < sinceUnix {
			continue
		}
		total++
		pathCount[h.Path]++
		if h.Tag != "" {
			tagCount[h.Tag]++
		}
		if h.Domain != "" {
			domainCount[h.Domain]++
		}
		idx := int(time.Unix(h.TS, 0).Sub(bucketStart) / bucketDur)
		if idx >= 0 && idx < nBuckets {
			buckets[idx].Count++
		}
	}

	return HitStats{
		Window:     window,
		Buckets:    buckets,
		Total:      total,
		TopPaths:   topN(pathCount, 10),
		TopTags:    topN(tagCount, 8),
		TopDomains: topN(domainCount, 8),
	}
}

func topN(m map[string]int64, n int) []HitRank {
	out := make([]HitRank, 0, len(m))
	for k, v := range m {
		out = append(out, HitRank{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	if len(out) > 0 && out[0].Count > 0 {
		top := out[0].Count
		for i := range out {
			out[i].Pct = int(out[i].Count * 100 / top)
			if out[i].Pct == 0 && out[i].Count > 0 {
				out[i].Pct = 1
			}
		}
	}
	return out
}

// MatchBlocked decides whether an incoming request (identified by hostname +
// raw request URI) should be blocked, based on the tags assigned to that
// domain and the enabled path rules for those tags.
func (s *Store) MatchBlocked(hostname, requestURI string) (PathRule, bool) {
	domain := normalizeDomain(hostname)
	reqPath := normalizeRequestPath(requestURI)

	s.mu.RLock()
	defer s.mu.RUnlock()

	var tags []string
	for _, d := range s.data.DomainTags {
		if d.Domain == domain {
			tags = d.Tags
			break
		}
	}
	if len(tags) == 0 {
		return PathRule{}, false
	}
	tagSet := map[string]bool{}
	for _, t := range tags {
		tagSet[t] = true
	}
	for _, r := range s.data.Rules {
		if !r.Enabled || !tagSet[r.Tag] {
			continue
		}
		if ruleMatches(r, reqPath) {
			return r, true
		}
	}
	return PathRule{}, false
}

func ruleMatches(r PathRule, reqPath string) bool {
	switch r.MatchType {
	case MatchExact:
		return reqPath == r.Path
	case MatchPrefix:
		p := strings.TrimSuffix(r.Path, "/")
		return reqPath == p || strings.HasPrefix(reqPath, p+"/")
	case MatchWildcard:
		matched, _ := path.Match(r.Path, reqPath)
		return matched
	default:
		return false
	}
}

func normalizeRequestPath(requestURI string) string {
	p := requestURI
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if strings.Contains(p, "%") {
		if decoded, err := url.PathUnescape(p); err == nil {
			p = decoded
		}
	}
	if p == "" {
		return "/"
	}
	cleaned := path.Clean(p)
	if cleaned != "/" && strings.HasSuffix(p, "/") {
		cleaned += "/"
	}
	return cleaned
}

var idCounter int64
var idMu sync.Mutex

func newID() string {
	idMu.Lock()
	defer idMu.Unlock()
	idCounter++
	return fmt.Sprintf("r%d%03d", time.Now().UnixNano()/1_000_000, idCounter%1000)
}
