package provider

// Volcengine Ark subscription usage: the plan's allowance read from the
// control plane with the account's AccessKey ID and Secret, probing
// GetAFPUsage (absolute) then GetCodingPlanUsage (percentages).
//
// The signature is Volcengine's AWS-SigV4 variant, fatal to copy from an
// S3/OSS signer: SignedHeaders is in the fixed order above (not sorted),
// the algorithm string is HMAC-SHA256 with no AWS4 prefix, the scope ends
// "request", and the date key is HMAC of the bare secret. Not davsync's.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	volcOpenAPIHost   = "open.volcengineapi.com"
	volcAPIVersion    = "2024-01-01"
	volcDefaultRegion = "cn-beijing"
	volcService       = "ark"
	volcContentType   = "application/json; charset=utf-8"
	volcSignedHeaders = "host;x-date;x-content-sha256;content-type"
	volcAKSKHint      = "Check the AccessKey ID / Secret are correct and the account has Ark usage-query (OpenAPI) permission"
)

// errVolcAuth is a credentials refusal (HTTP 401/403, or an error envelope
// naming one): both actions share the credentials, so the read stops.
var errVolcAuth = errors.New("volcengine auth")

// The three allowance kinds a Volcengine plan reports, as magpie names
// them, with the window's Span for routing. AFP reports them as its
// five-hour, weekly and monthly buckets; a Coding Plan names them per
// entry (volcWinName).
const (
	volcWin5h     = "5 hours"
	volcWinWeekly = "Weekly"
	volcWinMonth  = "Month"
)

// volcWindowSpan is the window's length, for routing; 0 when the kind is
// unknown.
func volcWindowSpan(name string) time.Duration {
	switch name {
	case volcWin5h:
		return 5 * time.Hour
	case volcWinWeekly:
		return 7 * 24 * time.Hour
	case volcWinMonth:
		return 30 * 24 * time.Hour
	}
	return 0
}

// volcengineSubscriptionUsage reads the configured volcengine provider's
// allowance, as another vendor's card is from fetchSubscriptionUsage.
func volcengineSubscriptionUsage(ctx context.Context) SubscriptionQuota {
	q := SubscriptionQuota{Provider: "volcengine", Name: "Volcengine Ark", Icon: "volcengine-color", Windows: []QuotaWindow{}}
	ak, sk, base, ok := volcengineCredential()
	if !ok {
		q.Error = "Volcengine Ark is not configured; add it to read its plan usage"
		return q
	}
	if ak == "" || sk == "" {
		q.Error = "Volcengine Ark usage needs the account's AccessKey ID and Secret (the control-plane credentials, not the inference API key). " + volcAKSKHint
		return q
	}
	region := volcRegion(base)

	var problems []string
	// Agent Plan first: its AFP buckets are absolute, and an account on one
	// reports them. Empty falls through to the Coding Plan.
	raw, err := volcOpenAPICall(ctx, region, ak, sk, "GetAFPUsage")
	switch {
	case errors.Is(err, errVolcAuth):
		q.Error = err.Error()
		return q
	case err != nil:
		problems = append(problems, "GetAFPUsage: "+err.Error())
	default:
		result := volcResult(raw)
		if ws := volcParseAFP(result); len(ws) > 0 {
			q.Windows = ws
			if p, _ := result["PlanType"].(string); strings.TrimSpace(p) != "" {
				q.Plan = "Agent Plan " + strings.TrimSpace(p)
			}
			return q
		}
		problems = append(problems, "GetAFPUsage: no Agent Plan allowance. Raw: "+volcRawSummary(raw))
	}

	raw, err = volcOpenAPICall(ctx, region, ak, sk, "GetCodingPlanUsage")
	switch {
	case errors.Is(err, errVolcAuth):
		q.Error = err.Error()
		return q
	case err != nil:
		problems = append(problems, "GetCodingPlanUsage: "+err.Error())
	default:
		if ws := volcParseCodingPlan(volcResult(raw)); len(ws) > 0 {
			q.Windows = ws
			q.Plan = "Coding Plan"
			return q
		}
		problems = append(problems, "GetCodingPlanUsage: no Coding Plan allowance. Raw: "+volcRawSummary(raw))
	}

	q.Error = strings.Join(problems, "; ")
	return q
}

// volcengineCredential is the configured volcengine provider's control-plane
// AccessKey ID and Secret, and the base URL its region is read from.
func volcengineCredential() (ak, sk, base string, ok bool) {
	for _, p := range load().Providers {
		if p.ID != "volcengine" {
			continue
		}
		base = p.Chat
		if base == "" {
			base = p.Responses
		}
		if base == "" {
			base = p.Anthropic
		}
		return p.AccessKeyID, p.SecretAccessKey, base, true
	}
	return "", "", "", false
}

// volcResult is a response's Result object, or the whole body when it has
// none.
func volcResult(raw []byte) map[string]any {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	if result, _ := body["Result"].(map[string]any); result != nil {
		return result
	}
	return body
}

// volcRawSummary is the head of a response, for a card to say what was
// actually answered when no field parsed.
func volcRawSummary(raw []byte) string {
	s := string(raw)
	if len(s) > 700 {
		s = s[:700]
	}
	return s
}

// volcHMACSHA256 is HMAC-SHA256 as Volcengine signs with it.
func volcHMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// volcSHA256Hex is the lowercase hex SHA-256 of data.
func volcSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// volcPercentEncode is RFC3986 encoding: everything but the unreserved
// set A-Z a-z 0-9 - _ . ~ is %XX, and a space is %20, never +.
func volcPercentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// volcRegion is the region a plan's endpoint lives in: the first cn- or
// ap- label of its host, cn-beijing when it names none.
func volcRegion(baseURL string) string {
	host := baseURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	for _, p := range strings.Split(host, ".") {
		if strings.HasPrefix(p, "cn-") || strings.HasPrefix(p, "ap-") {
			return p
		}
	}
	return volcDefaultRegion
}

// volcIsAuthErrorCode says a Volcengine error code names a credentials
// refusal, so the read stops rather than tries the next action.
func volcIsAuthErrorCode(code string) bool {
	c := strings.ToLower(code)
	for _, kw := range []string{"auth", "signature", "accessdenied", "denied",
		"unauthorized", "forbidden", "credential", "token"} {
		if strings.Contains(c, kw) {
			return true
		}
	}
	return false
}

// volcResponseError is a response's error envelope: ResponseMetadata.Error
// first, then a top-level Error.
func volcResponseError(body map[string]any) (code, msg string, ok bool) {
	var e map[string]any
	if meta, _ := body["ResponseMetadata"].(map[string]any); meta != nil {
		e, _ = meta["Error"].(map[string]any)
	}
	if e == nil {
		e, _ = body["Error"].(map[string]any)
	}
	if e == nil {
		return "", "", false
	}
	code, _ = e["Code"].(string)
	msg, _ = e["Message"].(string)
	if code == "" && msg == "" {
		return "", "", false
	}
	return code, msg, true
}

// volcCanonicalQuery is the request's query string: Action, Region and
// Version, in that fixed order, each RFC3986-encoded. The same string is
// the URL's query and the signer's, so the two can never differ.
func volcCanonicalQuery(action, region string) string {
	pairs := [][2]string{{"Action", action}, {"Region", region}, {"Version", volcAPIVersion}}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, volcPercentEncode(p[0])+"="+volcPercentEncode(p[1]))
	}
	return strings.Join(parts, "&")
}

// volcSign returns the Authorization, X-Date and X-Content-Sha256 headers
// for a request. canonicalQuery must be exactly the URL's query.
func volcSign(ak, sk, region, canonicalQuery string, body []byte, now time.Time) (auth, xDate, contentSHA string) {
	xDate = now.UTC().Format("20060102T150405Z")
	shortDate := now.UTC().Format("20060102")
	contentSHA = volcSHA256Hex(body)

	// the fixed header order above, each line ending, then a blank line
	canonicalHeaders := "host:" + volcOpenAPIHost + "\n" +
		"x-date:" + xDate + "\n" +
		"x-content-sha256:" + contentSHA + "\n" +
		"content-type:" + volcContentType + "\n"
	canonicalRequest := "POST\n/\n" + canonicalQuery + "\n" + canonicalHeaders + "\n" +
		volcSignedHeaders + "\n" + contentSHA

	scope := shortDate + "/" + region + "/" + volcService + "/request"
	stringToSign := "HMAC-SHA256\n" + xDate + "\n" + scope + "\n" + volcSHA256Hex([]byte(canonicalRequest))

	kDate := volcHMACSHA256([]byte(sk), []byte(shortDate))
	kRegion := volcHMACSHA256(kDate, []byte(region))
	kService := volcHMACSHA256(kRegion, []byte(volcService))
	kSigning := volcHMACSHA256(kService, []byte("request"))
	sig := hex.EncodeToString(volcHMACSHA256(kSigning, []byte(stringToSign)))

	auth = "HMAC-SHA256 Credential=" + ak + "/" + scope +
		", SignedHeaders=" + volcSignedHeaders + ", Signature=" + sig
	return auth, xDate, contentSHA
}

// volcOpenAPICall asks one control-plane action with no body. A credentials
// refusal is errVolcAuth; every other failure is an ordinary error.
func volcOpenAPICall(ctx context.Context, region, ak, sk, action string) ([]byte, error) {
	q := volcCanonicalQuery(action, region)
	url := "https://" + volcOpenAPIHost + "/?" + q
	auth, xDate, contentSHA := volcSign(ak, sk, region, q, nil, time.Now())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("volcengine: %v", err)
	}
	req.Header.Set("X-Date", xDate)
	req.Header.Set("X-Content-Sha256", contentSHA)
	req.Header.Set("Content-Type", volcContentType)
	req.Header.Set("Authorization", auth)

	// no single-request timeout: the refresh's ctx bounds the whole read
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("volcengine: network: %v", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("volcengine: read body: %v", err)
	}

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: HTTP %d. %s", errVolcAuth, res.StatusCode, volcAKSKHint)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var body map[string]any
		if json.Unmarshal(raw, &body) == nil {
			if code, msg, ok := volcResponseError(body); ok {
				if volcIsAuthErrorCode(code) {
					return nil, fmt.Errorf("%w: HTTP %d, %s: %s. %s", errVolcAuth, res.StatusCode, code, msg, volcAKSKHint)
				}
				return nil, fmt.Errorf("volcengine: HTTP %d, %s: %s", res.StatusCode, code, msg)
			}
		}
		return nil, fmt.Errorf("volcengine: HTTP %d: %s", res.StatusCode, volcRawSummary(raw))
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("volcengine: parse: %v", err)
	}
	// a 200 can carry a business error envelope too
	if code, msg, ok := volcResponseError(body); ok {
		if volcIsAuthErrorCode(code) {
			return nil, fmt.Errorf("%w: %s: %s. %s", errVolcAuth, code, msg, volcAKSKHint)
		}
		return nil, fmt.Errorf("volcengine: %s: %s", code, msg)
	}
	return raw, nil
}

// volcResetTime is a reset as the vendor sends it: an RFC3339 string, or
// seconds or milliseconds since the epoch; nil for one it doesn't give or
// gives as not yet set.
func volcResetTime(v any) *time.Time {
	switch x := v.(type) {
	case string:
		if s := strings.TrimSpace(x); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return &t
			}
		}
	case float64:
		n := int64(x)
		if n <= 0 {
			return nil
		}
		if n < 1_000_000_000_000 {
			n *= 1000
		}
		t := time.UnixMilli(n).UTC()
		return &t
	}
	return nil
}

// volcNum is a JSON number, or a string of one.
func volcNum(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// volcWinKind maps a Coding Plan entry's own name for a window to
// magpie's; "" for one it doesn't know, which is skipped.
func volcWinKind(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "session", "5h", "fivehour", "five_hour", "rolling_5h":
		return volcWin5h
	case "weekly", "week", "7d", "1w":
		return volcWinWeekly
	case "monthly", "month", "30d":
		return volcWinMonth
	}
	return ""
}

// volcParseAFP reads an Agent Plan result: Used/Quota per bucket. A bucket
// with no quota is an account not on the plan, so it is skipped; AFPDaily too.
func volcParseAFP(result map[string]any) []QuotaWindow {
	var out []QuotaWindow
	for _, w := range []struct{ key, name string }{
		{"AFPFiveHour", volcWin5h}, {"AFPWeekly", volcWinWeekly}, {"AFPMonthly", volcWinMonth},
	} {
		win, _ := result[w.key].(map[string]any)
		if win == nil {
			continue
		}
		quota, _ := volcNum(win["Quota"])
		if quota <= 0 {
			continue
		}
		used, _ := volcNum(win["Used"])
		out = append(out, QuotaWindow{
			Name:     w.name,
			Used:     used / quota * 100,
			ResetsAt: volcResetTime(win["ResetTime"]),
			Span:     volcWindowSpan(w.name),
		})
	}
	return out
}

// volcParseCodingPlan reads a Coding Plan (GetCodingPlanUsage) result: each
// entry's percentage, by the names several versions of the API have used.
func volcParseCodingPlan(result map[string]any) []QuotaWindow {
	arr, _ := result["QuotaUsage"].([]any)
	if arr == nil {
		arr, _ = result["Usages"].([]any)
	}
	if arr == nil {
		arr, _ = result["Details"].([]any)
	}
	var out []QuotaWindow
	for _, it := range arr {
		item, _ := it.(map[string]any)
		if item == nil {
			continue
		}
		label := ""
		for _, k := range []string{"Level", "Type", "Period", "Label", "Window"} {
			if s, ok := item[k].(string); ok && strings.TrimSpace(s) != "" {
				label = s
				break
			}
		}
		name := volcWinKind(label)
		if name == "" {
			continue
		}
		used := 0.0
		for _, k := range []string{"Percent", "UsedPercent", "UsagePercent"} {
			if f, ok := volcNum(item[k]); ok {
				used = f
				break
			}
		}
		reset := item["ResetTime"]
		if reset == nil {
			reset = item["ResetTimestamp"]
		}
		out = append(out, QuotaWindow{Name: name, Used: used, ResetsAt: volcResetTime(reset), Span: volcWindowSpan(name)})
	}
	return out
}
