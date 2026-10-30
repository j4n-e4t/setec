// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/server"
	"github.com/tailscale/setec/setectest"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// whoIsWith returns a WhoIs function granting the given actions on all secrets.
func whoIsWith(t *testing.T, actions ...acl.Action) func(context.Context, string) (*apitype.WhoIsResponse, error) {
	t.Helper()
	rule, err := json.Marshal(acl.Rule{Action: actions, Secret: []acl.Secret{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context, string) (*apitype.WhoIsResponse, error) {
		return &apitype.WhoIsResponse{
			Node:        &tailcfg.Node{Name: "example.com"},
			UserProfile: &tailcfg.UserProfile{LoginName: "[EMAIL]"},
			CapMap:      tailcfg.PeerCapMap{server.ACLCap: {tailcfg.RawMessage(rule)}},
		}, nil
	}
}

func uiGet(h http.Handler, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
	return w
}

// uiPost sends a form POST like htmx does from a same-origin page.
func uiPost(h http.Handler, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("HX-Request", "true")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestUIPages(t *testing.T) {
	d := setectest.NewDB(t, nil)
	d.MustPut(d.Superuser, "prod/db/password", "hunter2")
	d.MustPut(d.Superuser, "prod/db/password", "hunter3")
	ss := setectest.NewServer(t, d, nil)

	if w := uiGet(ss.Mux, "/"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "prod/db/password") {
		t.Errorf("GET /: got %d, body missing secret name:\n%s", w.Code, w.Body)
	}
	w := uiGet(ss.Mux, "/secret?name=prod%2Fdb%2Fpassword")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /secret: got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Reveal", "/ui/activate", "/ui/delete-version", "Add a new version", "Delete secret"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page missing %q", want)
		}
	}
	if strings.Contains(body, "hunter") {
		t.Error("detail page contains a secret value before it was revealed")
	}

	if w := uiGet(ss.Mux, "/secret?name=missing"); w.Code != http.StatusNotFound {
		t.Errorf("GET missing secret: got %d, want 404", w.Code)
	}
	if w := uiGet(ss.Mux, "/no/such/page"); w.Code != http.StatusNotFound {
		t.Errorf("GET unknown path: got %d, want 404", w.Code)
	}
}

func TestUIPermissions(t *testing.T) {
	d := setectest.NewDB(t, nil)
	d.MustPut(d.Superuser, "test", "v1")
	d.MustPut(d.Superuser, "test", "v2")
	ss := setectest.NewServer(t, d, &setectest.ServerOptions{
		WhoIs: whoIsWith(t, acl.ActionInfo),
	})

	body := uiGet(ss.Mux, "/secret?name=test").Body.String()
	for _, bad := range []string{"/ui/reveal", "/ui/activate", "/ui/delete", "/ui/put"} {
		if strings.Contains(body, bad) {
			t.Errorf("info-only caller sees control for %s", bad)
		}
	}

	form := url.Values{"name": {"test"}, "version": {"1"}}
	if w := uiPost(ss.Mux, "/ui/reveal", form, nil); w.Code != http.StatusForbidden {
		t.Errorf("reveal without get permission: got %d, want 403", w.Code)
	}
	if w := uiPost(ss.Mux, "/ui/activate", form, nil); w.Code != http.StatusForbidden {
		t.Errorf("activate without permission: got %d, want 403", w.Code)
	}
}

func TestUICrossOrigin(t *testing.T) {
	d := setectest.NewDB(t, nil)
	d.MustPut(d.Superuser, "test", "sekrit")
	ss := setectest.NewServer(t, d, nil)
	form := url.Values{"name": {"test"}, "version": {"1"}}

	tests := []struct {
		name string
		hdr  map[string]string
	}{
		{"CrossSite", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"ForeignOrigin", map[string]string{"Sec-Fetch-Site": "", "Origin": "https://evil.example"}},
		{"NoHXRequest", map[string]string{"HX-Request": ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := uiPost(ss.Mux, "/ui/reveal", form, tc.hdr)
			if w.Code != http.StatusForbidden {
				t.Errorf("got %d, want 403", w.Code)
			}
			if strings.Contains(w.Body.String(), "sekrit") {
				t.Error("response leaked secret value")
			}
		})
	}

	w := httptest.NewRecorder()
	ss.Mux.ServeHTTP(w, httptest.NewRequest("GET", "/ui/reveal?name=test&version=1", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET reveal: got %d, want 405", w.Code)
	}
}

func TestUIEdit(t *testing.T) {
	d := setectest.NewDB(t, nil)
	ss := setectest.NewServer(t, d, nil)

	// Create a secret, then add and activate a second version.
	w := uiPost(ss.Mux, "/ui/put", url.Values{"name": {"svc/key"}, "value": {"one\r\ntwo"}}, nil)
	if w.Code != http.StatusOK || w.Header().Get("HX-Redirect") != "/secret?name=svc%2Fkey" {
		t.Fatalf("create: got %d, redirect %q", w.Code, w.Header().Get("HX-Redirect"))
	}
	w = uiPost(ss.Mux, "/ui/put", url.Values{"name": {"svc/key"}, "value": {"three"}, "activate": {"1"}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("put+activate: got %d: %s", w.Code, w.Body)
	}
	if got := d.MustGet(d.Superuser, "svc/key"); got.Version != 2 || string(got.Value) != "three" {
		t.Errorf("active value: got v%d %q, want v2 %q", got.Version, got.Value, "three")
	}

	// Reveal normalizes the browser's CRLF line endings.
	w = uiPost(ss.Mux, "/ui/reveal", url.Values{"name": {"svc/key"}, "version": {"1"}}, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "one\ntwo") {
		t.Errorf("reveal v1: got %d:\n%s", w.Code, w.Body)
	}

	// Empty values are rejected with a message in the flash area.
	w = uiPost(ss.Mux, "/ui/put", url.Values{"name": {"svc/key"}}, nil)
	if w.Code != http.StatusBadRequest || w.Header().Get("HX-Retarget") != "#flash" {
		t.Errorf("empty put: got %d, retarget %q", w.Code, w.Header().Get("HX-Retarget"))
	}

	// Activate v1 again, then delete v2.
	ver := url.Values{"name": {"svc/key"}, "version": {"1"}}
	if w := uiPost(ss.Mux, "/ui/activate", ver, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version 1 is now active") {
		t.Errorf("activate: got %d:\n%s", w.Code, w.Body)
	}
	ver.Set("version", "2")
	if w := uiPost(ss.Mux, "/ui/delete-version", ver, nil); w.Code != http.StatusOK {
		t.Errorf("delete-version: got %d:\n%s", w.Code, w.Body)
	}
	if info, err := d.Actual.Info(d.Superuser, "svc/key"); err != nil || len(info.Versions) != 1 {
		t.Errorf("versions after delete: got %v, %v; want [1]", info, err)
	}

	// Deleting the secret requires typing its name.
	del := url.Values{"name": {"svc/key"}, "confirm": {"svc/ke"}}
	if w := uiPost(ss.Mux, "/ui/delete", del, nil); w.Code != http.StatusBadRequest {
		t.Errorf("delete with bad confirmation: got %d, want 400", w.Code)
	}
	if _, err := d.Actual.Info(d.Superuser, "svc/key"); err != nil {
		t.Fatalf("secret missing after rejected delete: %v", err)
	}
	del.Set("confirm", "svc/key")
	if w := uiPost(ss.Mux, "/ui/delete", del, nil); w.Code != http.StatusOK || w.Header().Get("HX-Redirect") != "/" {
		t.Errorf("delete: got %d, redirect %q", w.Code, w.Header().Get("HX-Redirect"))
	}
	if w := uiGet(ss.Mux, "/secret?name=svc%2Fkey"); w.Code != http.StatusNotFound {
		t.Errorf("deleted secret: got %d, want 404", w.Code)
	}
}
