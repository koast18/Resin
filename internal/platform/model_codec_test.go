package platform

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/Resinat/Resin/internal/model"
)

func TestBuildFromModel_Success(t *testing.T) {
	mp := model.Platform{
		ID:                               "plat-1",
		Name:                             "Platform-1",
		StickyTTLNs:                      3600,
		RegexFilters:                     []string{`^us-.*$`},
		RegionFilters:                    []string{"us", "jp"},
		ReverseProxyMissAction:           "REJECT",
		ReverseProxyEmptyAccountBehavior: "FIXED_HEADER",
		ReverseProxyFixedAccountHeader:   "x-account-id",
		AllocationPolicy:                 "PREFER_LOW_LATENCY",
		PassiveCircuitBreakerDisabled:    true,
	}

	plat, err := BuildFromModel(mp)
	if err != nil {
		t.Fatalf("BuildFromModel: %v", err)
	}

	if plat.ID != mp.ID || plat.Name != mp.Name {
		t.Fatalf("id/name mismatch: got (%q,%q)", plat.ID, plat.Name)
	}
	if plat.StickyTTLNs != mp.StickyTTLNs {
		t.Fatalf("sticky ttl mismatch: got %d want %d", plat.StickyTTLNs, mp.StickyTTLNs)
	}
	if plat.ReverseProxyMissAction != mp.ReverseProxyMissAction {
		t.Fatalf("miss action mismatch: got %q want %q", plat.ReverseProxyMissAction, mp.ReverseProxyMissAction)
	}
	if plat.ReverseProxyEmptyAccountBehavior != "FIXED_HEADER" {
		t.Fatalf(
			"empty-account behavior mismatch: got %q want %q",
			plat.ReverseProxyEmptyAccountBehavior,
			"FIXED_HEADER",
		)
	}
	if plat.ReverseProxyFixedAccountHeader != "X-Account-Id" {
		t.Fatalf(
			"fixed account header mismatch: got %q want %q",
			plat.ReverseProxyFixedAccountHeader,
			"X-Account-Id",
		)
	}
	if plat.AllocationPolicy != AllocationPolicyPreferLowLatency {
		t.Fatalf("allocation policy mismatch: got %q want %q", plat.AllocationPolicy, AllocationPolicyPreferLowLatency)
	}
	if !plat.PassiveCircuitBreakerDisabled {
		t.Fatal("passive circuit breaker flag mismatch: got false want true")
	}
	if len(plat.RegexFilters.Any) != 1 || !plat.RegexFilters.Any[0].MatchString("us-node") {
		t.Fatalf("regex filters not compiled as expected: %+v", plat.RegexFilters)
	}
	if len(plat.RegionFilters) != 2 || plat.RegionFilters[0] != "us" || plat.RegionFilters[1] != "jp" {
		t.Fatalf("region filters mismatch: %+v", plat.RegionFilters)
	}
}

func TestBuildFromModel_InvalidRegex(t *testing.T) {
	_, err := BuildFromModel(model.Platform{
		ID:           "plat-1",
		RegexFilters: []string{`(broken`},
	})
	if err == nil {
		t.Fatal("expected regex decode error")
	}
	if !strings.Contains(err.Error(), "regex_filters") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildFromModel_InvalidRegionFilters(t *testing.T) {
	_, err := BuildFromModel(model.Platform{
		ID:            "plat-1",
		RegexFilters:  []string{},
		RegionFilters: []string{"US"},
	})
	if err == nil {
		t.Fatal("expected region decode error")
	}
	if !strings.Contains(err.Error(), "region_filters[0]") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildFromModel_InvalidMissAction(t *testing.T) {
	_, err := BuildFromModel(model.Platform{
		ID:                     "plat-1",
		Name:                   "Platform-1",
		RegexFilters:           []string{},
		RegionFilters:          []string{},
		ReverseProxyMissAction: "RANDOM",
		AllocationPolicy:       "BALANCED",
	})
	if err == nil {
		t.Fatal("expected reverse_proxy_miss_action decode error")
	}
	if !strings.Contains(err.Error(), "reverse_proxy_miss_action") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildFromModel_InvalidEmptyAccountBehaviorFallsBackToRandom(t *testing.T) {
	plat, err := BuildFromModel(model.Platform{
		ID:                               "plat-1",
		Name:                             "Platform-1",
		RegexFilters:                     []string{},
		RegionFilters:                    []string{},
		ReverseProxyMissAction:           "TREAT_AS_EMPTY",
		ReverseProxyEmptyAccountBehavior: "INVALID",
		AllocationPolicy:                 "BALANCED",
	})
	if err != nil {
		t.Fatalf("BuildFromModel: %v", err)
	}
	if plat.ReverseProxyEmptyAccountBehavior != string(ReverseProxyEmptyAccountBehaviorRandom) {
		t.Fatalf(
			"empty-account behavior fallback mismatch: got %q, want %q",
			plat.ReverseProxyEmptyAccountBehavior,
			ReverseProxyEmptyAccountBehaviorRandom,
		)
	}
}

func TestBuildFromModel_FixedHeadersMultiLineNormalized(t *testing.T) {
	plat, err := BuildFromModel(model.Platform{
		ID:                               "plat-1",
		Name:                             "Platform-1",
		RegexFilters:                     []string{},
		RegionFilters:                    []string{},
		ReverseProxyMissAction:           "TREAT_AS_EMPTY",
		ReverseProxyEmptyAccountBehavior: "FIXED_HEADER",
		ReverseProxyFixedAccountHeader:   " authorization \nX-Account-Id\nx-account-id",
		AllocationPolicy:                 "BALANCED",
	})
	if err != nil {
		t.Fatalf("BuildFromModel: %v", err)
	}

	if plat.ReverseProxyFixedAccountHeader != "Authorization\nX-Account-Id" {
		t.Fatalf(
			"fixed account header mismatch: got %q, want %q",
			plat.ReverseProxyFixedAccountHeader,
			"Authorization\nX-Account-Id",
		)
	}
	if !reflect.DeepEqual(plat.ReverseProxyFixedAccountHeaders, []string{"Authorization", "X-Account-Id"}) {
		t.Fatalf(
			"fixed account headers mismatch: got %v, want %v",
			plat.ReverseProxyFixedAccountHeaders,
			[]string{"Authorization", "X-Account-Id"},
		)
	}
}

func TestBuildFromModel_FixedHeaderRequiresValidHeaderName(t *testing.T) {
	_, err := BuildFromModel(model.Platform{
		ID:                               "plat-1",
		RegexFilters:                     []string{},
		RegionFilters:                    []string{},
		ReverseProxyMissAction:           "TREAT_AS_EMPTY",
		ReverseProxyEmptyAccountBehavior: "FIXED_HEADER",
		ReverseProxyFixedAccountHeader:   "bad header",
	})
	if err == nil {
		t.Fatal("expected fixed header validation error")
	}
	if !strings.Contains(err.Error(), "reverse_proxy_fixed_account_header") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompileRegexFilters_Invalid(t *testing.T) {
	_, err := CompileRegexFilters([]string{"(broken"})
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "regex_filters[0]") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompileRegexFilters_RuleKindsAndEscapes(t *testing.T) {
	compiled, err := CompileRegexFilters([]string{
		"hk",
		"jp",
		"*fast",
		"!expired",
		`\!literal-bang`,
		`\*literal-star`,
		`*!required-bang`,
		`*\!required-bang`,
		`!!blocked-bang`,
		`!\*blocked-star`,
	})
	if err != nil {
		t.Fatalf("CompileRegexFilters: %v", err)
	}
	if len(compiled.Any) != 4 || len(compiled.Must) != 3 || len(compiled.MustNot) != 3 {
		t.Fatalf("unexpected compiled groups: %+v", compiled)
	}
	if !compiled.Any[2].MatchString("!literal-bang") {
		t.Fatal(`\! at line start should remain a regular escaped regex`)
	}
	if !compiled.Any[3].MatchString("*literal-star") {
		t.Fatal(`\* at line start should remain a regular escaped regex`)
	}
	if !compiled.Must[1].MatchString("!required-bang") {
		t.Fatal("a rule operator must only be parsed once")
	}
	if !compiled.Must[2].MatchString("!required-bang") {
		t.Fatal(`the MUST body should be passed to regexp unchanged`)
	}
	if !compiled.MustNot[1].MatchString("!blocked-bang") {
		t.Fatal("a MUST_NOT body must not be parsed for another operator")
	}
	if !compiled.MustNot[2].MatchString("*blocked-star") {
		t.Fatal(`the MUST_NOT body should be passed to regexp unchanged`)
	}
}

func TestCompileRegexFilters_InvalidOperatorBody(t *testing.T) {
	_, err := CompileRegexFilters([]string{"ok", "*(broken"})
	if err == nil {
		t.Fatal("expected invalid MUST regex body")
	}
	if !strings.Contains(err.Error(), "regex_filters[1]") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRegionFilters_Invalid(t *testing.T) {
	err := ValidateRegionFilters([]string{"US"})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "region_filters[0]") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompileEgressIPFilters_Valid(t *testing.T) {
	f, err := CompileEgressIPFilters([]string{
		"1.2.3.4",         // bare IPv4
		"45.90.0.0/16",    // IPv4 CIDR
		"2001:db8::1",     // bare IPv6
		"2001:db8::/32",   // IPv6 CIDR
		"!203.0.113.0/24", // negation
		" 9.9.9.9 ",       // surrounding spaces trimmed
		"",                // blank line skipped
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.Includes) != 5 {
		t.Fatalf("expected 5 include prefixes, got %d", len(f.Includes))
	}
	if len(f.Excludes) != 1 {
		t.Fatalf("expected 1 exclude prefix, got %d", len(f.Excludes))
	}
	if !f.Includes[0].Contains(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("bare IPv4 should compile to a /32 prefix")
	}
	// Host bits in a CIDR must be masked to a network prefix.
	if got := f.Includes[1].String(); got != "45.90.0.0/16" {
		t.Fatalf("expected masked prefix 45.90.0.0/16, got %s", got)
	}
	if got := f.Includes[3].String(); got != "2001:db8::/32" {
		t.Fatalf("expected IPv6 prefix 2001:db8::/32, got %s", got)
	}
	if f.Includes[4].String() != "9.9.9.9/32" {
		t.Fatalf("expected 9.9.9.9/32, got %s", f.Includes[4].String())
	}
}

func TestCompileEgressIPFilters_Invalid(t *testing.T) {
	cases := []struct {
		name  string
		rules []string
	}{
		{name: "garbage ip", rules: []string{"not-an-ip"}},
		{name: "bad cidr", rules: []string{"45.90.0.0/99"}},
		{name: "bad negation", rules: []string{"!whatever"}},
		{name: "ipv4 trailing junk", rules: []string{"1.2.3.4/33"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileEgressIPFilters(tc.rules)
			if err == nil {
				t.Fatalf("expected error for %v", tc.rules)
			}
			if !strings.Contains(err.Error(), "egress_ip_filters[0]") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildFromModel_EgressIPFilters(t *testing.T) {
	mp := model.Platform{
		ID: "p1", Name: "Default", StickyTTLNs: 1,
		RegexFilters:           []string{},
		RegionFilters:          []string{},
		EgressIPFilters:        []string{"1.2.3.0/24", "!1.2.3.9"},
		ReverseProxyMissAction: "TREAT_AS_EMPTY",
		AllocationPolicy:       "BALANCED",
	}
	plat, err := BuildFromModel(mp)
	if err != nil {
		t.Fatalf("BuildFromModel: %v", err)
	}
	if len(plat.EgressIPFilters.Includes) != 1 || len(plat.EgressIPFilters.Excludes) != 1 {
		t.Fatalf("unexpected compiled filters: %+v", plat.EgressIPFilters)
	}
	if !plat.EgressIPFilters.Matches(netip.MustParseAddr("1.2.3.8")) {
		t.Fatal("1.2.3.8 should match include 1.2.3.0/24")
	}
	if plat.EgressIPFilters.Matches(netip.MustParseAddr("1.2.3.9")) {
		t.Fatal("1.2.3.9 should be excluded")
	}
}

func TestBuildFromModel_InvalidEgressIPFilters(t *testing.T) {
	mp := model.Platform{
		ID: "p1", Name: "Default", StickyTTLNs: 1,
		RegexFilters:           []string{},
		RegionFilters:          []string{},
		EgressIPFilters:        []string{"not-an-ip"},
		ReverseProxyMissAction: "TREAT_AS_EMPTY",
		AllocationPolicy:       "BALANCED",
	}
	_, err := BuildFromModel(mp)
	if err == nil || !strings.Contains(err.Error(), "egress_ip_filters") {
		t.Fatalf("expected egress_ip_filters decode error, got %v", err)
	}
}
