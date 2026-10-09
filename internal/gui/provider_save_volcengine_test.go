package gui

// A Volcengine Ark provider's editor shows the account's control-plane
// AccessKey ID and whether a Secret is saved, never the Secret itself, and
// a Save that leaves the Secret blank keeps the saved one — as a key's own
// Save does.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

func TestProviderSaveKeepsVolcengineSecret(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	mux := http.NewServeMux()
	providerRoutes(mux, nil)
	post := func(body string) {
		t.Helper()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/provider/save", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}

	v, err := provider.FromPreset("volcengine")
	if err != nil {
		t.Fatal(err)
	}
	v.Key = "ark-key"
	v.AccessKeyID, v.SecretAccessKey = "AK-1", "SK-1"
	if err := provider.Save(v); err != nil {
		t.Fatal(err)
	}
	// the editor's own save: its form's fields, and the AccessKey ID it
	// typed, with the Secret field left blank
	base := `"id":"volcengine","from":"volcengine","name":"Volcengine Ark","preset":"volcengine","key":"","chat":"` +
		v.Chat + `","responses":"` + v.Responses + `","anthropic":"` + v.Anthropic +
		`","catalog":"volcengine","models":[],"headers":{},"searches":false,"pinUpstream":false,"unredacted":false,"contexts":{},"outputs":{},"compacts":{},"proxy":"","maxConcurrency":null,"queueLimit":0,"queueWait":0,"priceRate":null`

	post(`{` + base + `,"accessKeyID":"AK-2"}`)
	p, err := provider.Find("volcengine")
	if err != nil {
		t.Fatal(err)
	}
	if p.AccessKeyID != "AK-2" || p.SecretAccessKey != "SK-1" {
		t.Errorf("blank Secret: ak=%q sk=%q, want AK-2/SK-1", p.AccessKeyID, p.SecretAccessKey)
	}

	// a typed Secret replaces the saved one
	post(`{` + base + `,"accessKeyID":"AK-2","secretAccessKey":"SK-2"}`)
	if p, _ = provider.Find("volcengine"); p.SecretAccessKey != "SK-2" {
		t.Errorf("typed Secret: %q", p.SecretAccessKey)
	}

	// the listing tells the editor the AccessKey ID and that a Secret is
	// saved, and never the Secret
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/providers", nil))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "SK-2") {
		t.Error("the listing told the Secret")
	}
	var got struct {
		Providers []struct {
			ID              string `json:"id"`
			AccessKeyID     string `json:"accessKeyID"`
			AccessSecretSet bool   `json:"accessSecretSet"`
		} `json:"providers"`
		Presets []struct {
			ID         string `json:"id"`
			Volcengine bool   `json:"volcengine"`
		} `json:"presets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, x := range got.Providers {
		if x.ID != "volcengine" {
			continue
		}
		found = true
		if x.AccessKeyID != "AK-2" || !x.AccessSecretSet {
			t.Errorf("provider json: %+v", x)
		}
	}
	if !found {
		t.Fatal("the volcengine provider is not listed")
	}
	var gated bool
	for _, x := range got.Presets {
		if x.ID == "volcengine" && x.Volcengine {
			gated = true
		}
	}
	if !gated {
		t.Error("the volcengine preset isn't gated for the editor")
	}
}
