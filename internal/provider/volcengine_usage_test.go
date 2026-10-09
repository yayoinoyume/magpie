package provider

// The tests here use a local server with the rewrite transport, so no
// request ever leaves the machine: volcOpenAPIHost is only a header the
// signer names.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func volcTestHome(t *testing.T) {
	t.Helper()
	isolate(t)
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(h, ".cache"))
}

// volcAsk points every request at a local server and counts them. handler
// answers one Action's query with a status and a body.
func volcAsk(t *testing.T, handler func(action string) (int, string)) *int {
	t.Helper()
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		code, body := handler(r.URL.Query().Get("Action"))
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := http.DefaultClient.Transport
	http.DefaultClient.Transport = rewrite{srv}
	t.Cleanup(func() { http.DefaultClient.Transport = old })
	return &asked
}

func volcSave(t *testing.T, p Provider) {
	t.Helper()
	if p.ID == "" {
		p.ID = "volcengine"
	}
	if p.Name == "" {
		p.Name = "Volcengine Ark"
	}
	if p.Chat == "" {
		p.Chat = "https://ark.cn-beijing.volces.com/api/coding/v3"
	}
	if p.Key == "" {
		p.Key = "ark-key"
	}
	if err := Save(p); err != nil {
		t.Fatal(err)
	}
}

// TestVolcengineSign pins the signer to one vector. Volcengine refuses a
// call whose signature is off by a byte, and its three differences from
// AWS SigV4 are exactly the kind a copied signer gets wrong, so the same
// ak/sk/date must give the same authorization every time.
func TestVolcengineSign(t *testing.T) {
	ak, sk, region := "testak", "testsk", "cn-beijing"
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	q := volcCanonicalQuery("GetAFPUsage", region)
	if q != "Action=GetAFPUsage&Region=cn-beijing&Version=2024-01-01" {
		t.Fatalf("canonical query: %q", q)
	}
	auth, xDate, contentSHA := volcSign(ak, sk, region, q, nil, now)
	if xDate != "20260102T030405Z" {
		t.Errorf("x-date: %q", xDate)
	}
	if contentSHA != volcSHA256Hex(nil) || contentSHA != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("body hash: %q", contentSHA)
	}
	// the vector is the signature; the rest is built from the same parts so
	// the test doesn't spell a credential-shaped literal
	want := "HMAC-SHA256 Credential=" + ak + "/20260102/" + region + "/ark/request, SignedHeaders=" +
		volcSignedHeaders + ", Signature=ec8065432924d72010cc665d41761633ac5cb6df51f0a6b2fe17680a61f6ba32"
	if auth != want {
		t.Errorf("authorization:\n got %s\nwant %s", auth, want)
	}
}

func TestVolcengineRegion(t *testing.T) {
	for _, c := range []struct{ base, want string }{
		{"https://ark.cn-beijing.volces.com/api/coding/v3", "cn-beijing"},
		{"https://ark.ap-southeast-1.volces.com/api/plan/v3", "ap-southeast-1"},
		{"http://ark.cn-shanghai.volces.com/api/v3/", "cn-shanghai"},
		{"https://open.volcengineapi.com", "cn-beijing"},
		{"", "cn-beijing"},
	} {
		if got := volcRegion(c.base); got != c.want {
			t.Errorf("volcRegion(%q) = %q, want %q", c.base, got, c.want)
		}
	}
}

func TestVolcengineUsageAFP(t *testing.T) {
	volcTestHome(t)
	volcSave(t, Provider{AccessKeyID: "AK", SecretAccessKey: "SK"})
	n := volcAsk(t, func(action string) (int, string) {
		if action != "GetAFPUsage" {
			t.Errorf("asked %s", action)
			return 401, ""
		}
		return 200, `{"Result":{"PlanType":"pro",` +
			`"AFPFiveHour":{"Quota":100,"Used":42,"ResetTime":"2026-02-01T00:00:00Z"},` +
			`"AFPDaily":{"Quota":500,"Used":400},` +
			`"AFPWeekly":{"Quota":0,"Used":5},` +
			`"AFPMonthly":{"Quota":200,"Used":50}}}`
	})
	q := volcengineSubscriptionUsage(context.Background())
	if q.Error != "" || q.Provider != "volcengine" || q.Plan != "Agent Plan pro" || len(q.Windows) != 2 {
		t.Fatalf("card: %+v", q)
	}
	if w := q.Windows[0]; w.Name != volcWin5h || w.Used != 42 || w.Span != 5*time.Hour || w.ResetsAt == nil {
		t.Errorf("5-hour: %+v", w)
	}
	// daily is skipped, and a bucket with no quota is "not on the plan"
	if w := q.Windows[1]; w.Name != volcWinMonth || w.Used != 25 || w.Span != 30*24*time.Hour {
		t.Errorf("month: %+v", w)
	}
	if *n != 1 {
		t.Errorf("asked %d actions, want 1", *n)
	}
}

func TestVolcengineUsageCodingPlan(t *testing.T) {
	volcTestHome(t)
	volcSave(t, Provider{AccessKeyID: "AK", SecretAccessKey: "SK"})
	n := volcAsk(t, func(action string) (int, string) {
		switch action {
		case "GetAFPUsage":
			return 200, `{"Result":{}}`
		case "GetCodingPlanUsage":
			return 200, `{"Result":{"QuotaUsage":[` +
				`{"Level":"session","Percent":10,"ResetTimestamp":1790000000000},` +
				`{"Level":"monthly","Percent":33}]}}`
		}
		t.Errorf("asked %s", action)
		return 401, ""
	})
	q := volcengineSubscriptionUsage(context.Background())
	if q.Error != "" || q.Plan != "Coding Plan" || len(q.Windows) != 2 {
		t.Fatalf("card: %+v", q)
	}
	if w := q.Windows[0]; w.Name != volcWin5h || w.Used != 10 || w.ResetsAt == nil {
		t.Errorf("5-hour: %+v", w)
	}
	if w := q.Windows[1]; w.Name != volcWinMonth || w.Used != 33 {
		t.Errorf("month: %+v", w)
	}
	if *n != 2 {
		t.Errorf("asked %d actions, want 2", *n)
	}
}

// An auth refusal shares the credentials of both actions, so it stops the
// read rather than probing the next.
func TestVolcengineUsageAuthStops(t *testing.T) {
	for _, c := range []struct {
		name, code, body string
	}{
		{"envelope", "", `{"ResponseMetadata":{"Error":{"Code":"SignatureDoesNotMatch","Message":"bad sign"}}}`},
		{"status", "401", `{"Message":"no"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			volcTestHome(t)
			volcSave(t, Provider{AccessKeyID: "AK", SecretAccessKey: "SK"})
			n := volcAsk(t, func(action string) (int, string) {
				if action != "GetAFPUsage" {
					t.Errorf("asked %s after an auth refusal", action)
				}
				if c.code != "" {
					return 401, c.body
				}
				return 200, c.body
			})
			q := volcengineSubscriptionUsage(context.Background())
			if !strings.Contains(q.Error, "volcengine auth") || len(q.Windows) != 0 {
				t.Fatalf("card: %+v", q)
			}
			if *n != 1 {
				t.Errorf("asked %d actions, want 1", *n)
			}
		})
	}
}

// A non-auth failure is not a refusal: the next action is still probed.
func TestVolcengineUsageSoftErrorFallsThrough(t *testing.T) {
	volcTestHome(t)
	volcSave(t, Provider{AccessKeyID: "AK", SecretAccessKey: "SK"})
	n := volcAsk(t, func(action string) (int, string) {
		switch action {
		case "GetAFPUsage":
			return 200, `{"ResponseMetadata":{"Error":{"Code":"InternalError","Message":"oops"}}}`
		case "GetCodingPlanUsage":
			return 200, `{"Result":{"QuotaUsage":[{"Level":"weekly","Percent":7}]}}`
		}
		return 500, ""
	})
	q := volcengineSubscriptionUsage(context.Background())
	if q.Error != "" || q.Plan != "Coding Plan" || len(q.Windows) != 1 || q.Windows[0].Name != volcWinWeekly || q.Windows[0].Used != 7 {
		t.Fatalf("card: %+v", q)
	}
	if *n != 2 {
		t.Errorf("asked %d actions, want 2", *n)
	}
}

func TestVolcengineUsageEmpty(t *testing.T) {
	volcTestHome(t)
	volcSave(t, Provider{AccessKeyID: "AK", SecretAccessKey: "SK"})
	n := volcAsk(t, func(action string) (int, string) { return 200, `{"Result":{}}` })
	q := volcengineSubscriptionUsage(context.Background())
	if len(q.Windows) != 0 || !strings.Contains(q.Error, "GetAFPUsage") || !strings.Contains(q.Error, "GetCodingPlanUsage") {
		t.Fatalf("card: %+v", q)
	}
	if *n != 2 {
		t.Errorf("asked %d actions, want 2", *n)
	}
}

func TestVolcengineUsageNeedsAccessKey(t *testing.T) {
	volcTestHome(t)
	volcSave(t, Provider{})
	q := volcengineSubscriptionUsage(context.Background())
	if !strings.Contains(q.Error, "AccessKey ID") {
		t.Fatalf("card: %+v", q)
	}
}
