// updater.go — Automatic update checker
//
// Polls the GitHub Releases API on startup and every 24 hours.
// Compares the latest release tag against the running dsVersion.
// If a newer version exists, fires registered callbacks so tray.go
// can show a notification item in the menu.
//
// Design principles:
//   · Never auto-installs — user always decides
//   · Non-blocking — runs in a goroutine, never delays startup
//   · Fails silently — no network = no problem, update check is best-effort
//   · Respects user dismissal — once dismissed, won't re-notify for that version

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ── TYPES ────────────────────────────────────────────────────

type UpdateState struct {
	mu            sync.RWMutex
	latestVersion string // "v0.2.0" or ""
	available     bool
	dismissed     string         // version the user dismissed — don't re-notify
	callbacks     []func(string) // fired with new version string
	stopCh        chan struct{}
}

var updater = &UpdateState{
	stopCh: make(chan struct{}),
}

// ── GITHUB API RESPONSE ───────────────────────────────────────

type ghRelease struct {
	TagName    string `json:"tag_name"` // "v0.2.0"
	Prerelease bool   `json:"prerelease"`
	Draft      bool   `json:"draft"`
	HTMLURL    string `json:"html_url"` // release page URL
}

// ── INIT / SHUTDOWN ───────────────────────────────────────────

func initUpdater() {
	go updater.run()
	log.Printf("updater: started (current=%s)", dsVersion)
}

func shutdownUpdater() {
	select {
	case <-updater.stopCh:
	default:
		close(updater.stopCh)
	}
}

// ── POLLER ────────────────────────────────────────────────────

func (u *UpdateState) run() {
	// First check: 30 seconds after startup (let everything else settle)
	select {
	case <-u.stopCh:
		return
	case <-time.After(30 * time.Second):
	}
	u.check()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-u.stopCh:
			log.Println("updater: stopped")
			return
		case <-ticker.C:
			u.check()
		}
	}
}

func (u *UpdateState) check() {
	latest, url, err := fetchLatestRelease()
	if err != nil {
		log.Printf("updater: check failed (network issue): %v", err)
		return
	}
	if latest == "" {
		return // no stable release found
	}

	log.Printf("updater: latest=%s current=%s", latest, dsVersion)

	if !isNewer(latest, dsVersion) {
		return // already up to date
	}

	u.mu.Lock()
	u.latestVersion = latest
	u.available = true
	dismissed := u.dismissed
	cbs := u.callbacks
	u.mu.Unlock()

	if dismissed == latest {
		return // user already dismissed this version
	}

	WriteGoEvent("UPDATE_AVAILABLE",
		fmt.Sprintf("version:%s url:%s", latest, url), "ok")

	log.Printf("updater: update available → %s", latest)
	for _, cb := range cbs {
		go cb(latest)
	}
}

// ── GITHUB API ────────────────────────────────────────────────

const repoOwner = "chinmaykx07"
const repoName = "DevShield_Windows"

func fetchLatestRelease() (tag, url string, err error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest",
		repoOwner, repoName)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", fmt.Sprintf("DevShield/%s", dsVersion))

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", "", err
	}

	var release ghRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", "", err
	}

	if release.Draft || release.Prerelease {
		return "", "", nil // only notify for stable releases
	}

	return release.TagName, release.HTMLURL, nil
}

// ── SEMVER COMPARISON ─────────────────────────────────────────

// isNewer returns true if candidate is a higher version than current.
// Handles versions with or without a leading "v".
// Simple comparison: splits on "." and compares numerically segment by segment.
func isNewer(candidate, current string) bool {
	cv := parseVer(candidate)
	cc := parseVer(current)
	for i := 0; i < 3; i++ {
		if i >= len(cv) || i >= len(cc) {
			break
		}
		if cv[i] > cc[i] {
			return true
		}
		if cv[i] < cc[i] {
			return false
		}
	}
	return false
}

func parseVer(v string) []int {
	v = strings.TrimPrefix(v, "v")
	// Strip any pre-release suffix (e.g. "0.1.0-beta" → "0.1.0")
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 3)
	for i, p := range parts {
		if i >= 3 {
			break
		}
		n := 0
		fmt.Sscanf(p, "%d", &n)
		nums[i] = n
	}
	return nums
}

// ── PUBLIC API ────────────────────────────────────────────────

// OnUpdateAvailable registers a callback fired when a newer version is found.
// tray.go registers a function that adds a notification item to the menu.
func OnUpdateAvailable(cb func(version string)) {
	updater.mu.Lock()
	defer updater.mu.Unlock()
	updater.callbacks = append(updater.callbacks, cb)
}

// DismissUpdate marks the given version as dismissed.
// The user clicked "remind me later" or dismissed the tray item.
func DismissUpdate(version string) {
	updater.mu.Lock()
	updater.dismissed = version
	updater.mu.Unlock()
	log.Printf("updater: dismissed %s", version)
}

// IsUpdateAvailable returns the latest version string if an update is
// available and not dismissed, or "" if up to date.
func IsUpdateAvailable() string {
	updater.mu.RLock()
	defer updater.mu.RUnlock()
	if updater.available && updater.dismissed != updater.latestVersion {
		return updater.latestVersion
	}
	return ""
}

// OpenReleasePage opens the GitHub releases page in the default browser.
func OpenReleasePage() {
	url := fmt.Sprintf("https://github.com/%s/%s/releases/latest", repoOwner, repoName)
	cmd := exec.Command("cmd", "/c", "start", url)
	_ = cmd.Start()
	WriteGoEvent("UPDATE_PAGE_OPENED", url, "ok")
}
