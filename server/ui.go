// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/db"
	"github.com/tailscale/setec/types/api"
)

// maxUIValueSize is the largest secret value accepted from the web UI.
const maxUIValueSize = 1 << 20

// The web UI is served from the same mux as the API, but uses its own
// endpoints. The JSON API refuses all browser traffic (see serveJSON), so
// mutating UI endpoints instead defend against CSRF by requiring both a
// same-origin request (via Sec-Fetch-Site or Origin) and the HX-Request
// header, which cannot be set cross-origin without a CORS preflight.

func (s *Server) registerUI(mux *http.ServeMux) {
	mux.HandleFunc("/", s.htmlList)
	mux.HandleFunc("/secret", s.htmlSecret)
	mux.HandleFunc("/ui/masked", s.uiMasked)
	mux.HandleFunc("/ui/reveal", s.uiAction(s.uiReveal))
	mux.HandleFunc("/ui/put", s.uiAction(s.uiPut))
	mux.HandleFunc("/ui/activate", s.uiAction(s.uiActivate))
	mux.HandleFunc("/ui/delete-version", s.uiAction(s.uiDeleteVersion))
	mux.HandleFunc("/ui/delete", s.uiAction(s.uiDelete))
}

// uiPerms records which actions a caller may take on a secret, so that the
// UI can omit controls that would only fail. The database still enforces
// all permissions independently.
type uiPerms struct {
	Get, Put, Activate, Delete bool
}

func permsFor(caller db.Caller, name string) uiPerms {
	p := caller.Permissions
	return uiPerms{
		Get:      p.Allow(acl.ActionGet, name),
		Put:      p.Allow(acl.ActionPut, name),
		Activate: p.Allow(acl.ActionActivate, name),
		Delete:   p.Allow(acl.ActionDelete, name),
	}
}

func callerName(caller db.Caller) string {
	if caller.Principal.User != "" {
		return caller.Principal.User
	}
	return strings.Join(caller.Principal.Tags, ",")
}

type listPage struct {
	Caller  string
	Secrets []*api.SecretInfo
}

func (listPage) Title() string { return "Secrets" }

type secretPage struct {
	Caller   string
	Info     *api.SecretInfo
	Versions []api.SecretVersion // newest first
	Perms    uiPerms
}

func (p *secretPage) Title() string { return p.Info.Name }

type errorPage struct {
	Caller  string
	Message string
}

func (errorPage) Title() string { return "Error" }

type valueView struct {
	Name    string
	Version api.SecretVersion
	Size    int
	Text    string // set if the value is printable text
	Hex     string // set if the value is binary
	Base64  string
}

func (s *Server) htmlList(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path != "/" {
		http.NotFound(w, r)
		return
	}
	caller, ok := s.uiGetCaller(w, r)
	if !ok {
		return
	}

	infos, err := s.db.List(caller)
	if err != nil {
		s.uiPageError(w, path, err)
		return
	}
	s.render(w, path, "index.html", listPage{Caller: callerName(caller), Secrets: infos})
}

func (s *Server) htmlSecret(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	caller, ok := s.uiGetCaller(w, r)
	if !ok {
		return
	}
	page, err := s.secretPage(caller, r.FormValue("name"))
	if err != nil {
		s.uiPageError(w, path, err)
		return
	}
	s.render(w, path, "secret.html", page)
}

func (s *Server) secretPage(caller db.Caller, name string) (*secretPage, error) {
	info, err := s.db.Info(caller, name)
	if err != nil {
		return nil, err
	}
	vs := slices.Clone(info.Versions)
	slices.Sort(vs)
	slices.Reverse(vs)
	return &secretPage{
		Caller:   callerName(caller),
		Info:     info,
		Versions: vs,
		Perms:    permsFor(caller, name),
	}, nil
}

// uiMasked renders the placeholder for a hidden secret value. It does not
// touch the database, so it needs no identity check.
func (s *Server) uiMasked(w http.ResponseWriter, r *http.Request) {
	v, err := parseVersion(r.FormValue("version"))
	if err != nil {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	s.render(w, r.URL.Path, "masked", valueView{Name: r.FormValue("name"), Version: v})
}

func (s *Server) uiReveal(w http.ResponseWriter, r *http.Request, caller db.Caller) error {
	name := r.FormValue("name")
	v, err := parseVersion(r.FormValue("version"))
	if err != nil {
		return err
	}
	sv, err := s.db.GetVersion(caller, name, v)
	if err != nil {
		return err
	}
	view := valueView{
		Name:    name,
		Version: sv.Version,
		Size:    len(sv.Value),
		Base64:  base64.StdEncoding.EncodeToString(sv.Value),
	}
	if isPrintable(sv.Value) {
		view.Text = string(sv.Value)
	} else {
		view.Hex = hex.Dump(sv.Value)
	}
	s.render(w, r.URL.Path, "value", view)
	return nil
}

func (s *Server) uiPut(w http.ResponseWriter, r *http.Request, caller db.Caller) error {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		return uiError("a secret name is required")
	}
	value, err := formValue(r)
	if err != nil {
		return err
	}
	ver, err := s.db.Put(caller, name, value)
	if err != nil {
		return err
	}
	if r.FormValue("activate") != "" {
		if err := s.db.Activate(caller, name, ver); err != nil {
			return err
		}
	}
	w.Header().Set("HX-Redirect", secretURL(name))
	return nil
}

func (s *Server) uiActivate(w http.ResponseWriter, r *http.Request, caller db.Caller) error {
	name := r.FormValue("name")
	v, err := parseVersion(r.FormValue("version"))
	if err != nil {
		return err
	}
	if err := s.db.Activate(caller, name, v); err != nil {
		return err
	}
	return s.renderDetail(w, r, caller, name, fmt.Sprintf("Version %d is now active.", v))
}

func (s *Server) uiDeleteVersion(w http.ResponseWriter, r *http.Request, caller db.Caller) error {
	name := r.FormValue("name")
	v, err := parseVersion(r.FormValue("version"))
	if err != nil {
		return err
	}
	if err := s.db.DeleteVersion(caller, name, v); err != nil {
		return err
	}
	return s.renderDetail(w, r, caller, name, fmt.Sprintf("Deleted version %d.", v))
}

func (s *Server) uiDelete(w http.ResponseWriter, r *http.Request, caller db.Caller) error {
	name := r.FormValue("name")
	// Deleting a whole secret is irreversible, so the UI makes the user
	// type the secret name to confirm.
	if r.FormValue("confirm") != name {
		return uiError("confirmation did not match the secret name; nothing was deleted")
	}
	if err := s.db.Delete(caller, name); err != nil {
		return err
	}
	w.Header().Set("HX-Redirect", "/")
	return nil
}

// renderDetail re-renders the detail section of a secret page after a
// change, along with a status message.
func (s *Server) renderDetail(w http.ResponseWriter, r *http.Request, caller db.Caller, name, msg string) error {
	page, err := s.secretPage(caller, name)
	if err != nil {
		return err
	}
	s.render(w, r.URL.Path, "detail", page)
	s.render(w, r.URL.Path, "header-badges", page)
	s.render(w, r.URL.Path, "flash", flash{Message: msg})
	return nil
}

type flash struct {
	Message string
	Error   bool
}

// uiError is an error whose text is safe to show to the user.
type uiError string

func (e uiError) Error() string { return string(e) }

// uiAction wraps a mutating (or secret-revealing) UI handler with method,
// CSRF, and identity checks, and renders any error it reports into the
// page's flash area.
func (s *Server) uiAction(fn func(http.ResponseWriter, *http.Request, db.Caller) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		s.countCalls.Add(path, 1)
		w.Header().Set("Cache-Control", "no-store")

		if r.Method != "POST" {
			s.countCallBadRequest.Add(path, 1)
			http.Error(w, "only POST requests allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.csrf.Check(r); err != nil || r.Header.Get("HX-Request") != "true" {
			s.countCallForbidden.Add(path, 1)
			http.Error(w, "cross-origin request denied", http.StatusForbidden)
			return
		}
		caller, ok := s.uiGetCaller(w, r)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*maxUIValueSize)
		if err := r.ParseMultipartForm(maxUIValueSize); err != nil && !errors.Is(err, http.ErrNotMultipart) {
			s.countCallBadRequest.Add(path, 1)
			s.uiFlashError(w, http.StatusBadRequest, "invalid form submission")
			return
		}

		if err := fn(w, r, caller); err != nil {
			code, msg := s.classifyError(path, err)
			s.uiFlashError(w, code, msg)
		}
	}
}

func (s *Server) uiGetCaller(w http.ResponseWriter, r *http.Request) (db.Caller, bool) {
	caller, err := s.getIdentity(r)
	if err != nil {
		s.countCallInternalError.Add(r.URL.Path, 1)
		log.Printf("ui: identifying caller: %v", err)
		http.Error(w, "unable to identify caller", http.StatusInternalServerError)
		return db.Caller{}, false
	}
	return caller, true
}

// classifyError maps an error to an HTTP status and a message that is safe to
// show the user, updating metrics accordingly.
func (s *Server) classifyError(path string, err error) (int, string) {
	var ue uiError
	switch {
	case errors.As(err, &ue):
		s.countCallBadRequest.Add(path, 1)
		return http.StatusBadRequest, ue.Error()
	case errors.Is(err, db.ErrAccessDenied):
		s.countCallForbidden.Add(path, 1)
		return http.StatusForbidden, "Access denied: you do not have permission to do that."
	case errors.Is(err, db.ErrNotFound):
		s.countCallNotFound.Add(path, 1)
		return http.StatusNotFound, "Not found."
	default:
		s.countCallInternalError.Add(path, 1)
		log.Printf("ui: %s: %v", path, err)
		return http.StatusInternalServerError, "Internal error; see server logs."
	}
}

func (s *Server) uiPageError(w http.ResponseWriter, path string, err error) {
	code, msg := s.classifyError(path, err)
	w.WriteHeader(code)
	s.render(w, path, "error.html", errorPage{Message: msg})
}

// uiFlashError reports an error to an htmx request by retargeting the
// response into the page's flash area.
func (s *Server) uiFlashError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("HX-Retarget", "#flash")
	w.Header().Set("HX-Reswap", "outerHTML")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := s.tmpl.ExecuteTemplate(w, "flash", flash{Message: msg, Error: true}); err != nil {
		log.Printf("ui: rendering error: %v", err)
	}
}

func (s *Server) render(w http.ResponseWriter, path, name string, data any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.countCallInternalError.Add(path, 1)
		log.Printf("ui: rendering %s: %v", name, err)
	}
}

// formValue returns the secret value submitted in r, preferring an uploaded
// file over the text field.
func formValue(r *http.Request) ([]byte, error) {
	if f, _, err := r.FormFile("file"); err == nil {
		defer f.Close()
		value, err := io.ReadAll(io.LimitReader(f, maxUIValueSize+1))
		if err != nil {
			return nil, err
		}
		if len(value) > maxUIValueSize {
			return nil, uiError("uploaded file is too large")
		}
		if len(value) > 0 {
			return value, nil
		}
	}
	value := r.FormValue("value")
	if value == "" {
		return nil, uiError("a value is required (enter text or choose a file)")
	}
	// Browsers submit textarea line breaks as CRLF.
	return []byte(strings.ReplaceAll(value, "\r\n", "\n")), nil
}

func parseVersion(s string) (api.SecretVersion, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v == 0 {
		return 0, uiError("invalid version")
	}
	return api.SecretVersion(v), nil
}

func secretURL(name string) string {
	return "/secret?name=" + url.QueryEscape(name)
}

// isPrintable reports whether b is valid UTF-8 text without control
// characters other than common whitespace.
func isPrintable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// timeAgo formats t as a coarse duration relative to now.
func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// latestVersion returns the highest version in vs.
func latestVersion(vs []api.SecretVersion) api.SecretVersion {
	if len(vs) == 0 {
		return 0
	}
	return slices.Max(vs)
}

// initial returns the uppercased first letter of s, for avatars.
func initial(s string) string {
	for _, r := range s {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// jsonString returns s encoded as a JSON string, for use in hx-vals.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
