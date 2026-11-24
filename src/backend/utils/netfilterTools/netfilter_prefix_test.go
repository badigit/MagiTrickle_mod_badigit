package netfilterTools

import (
	"strings"
	"testing"
)

func TestNewValidatesCleanupPrefixes(t *testing.T) {
	for _, tt := range []struct {
		name, chain, ipset, wantError string
	}{
		{"defaults", "MT_", "mt_", ""},
		{"custom", "CUSTOM_", "custom_", ""},
		{"empty chain", "", "mt_", "chain prefix"},
		{"short chain", "MT", "mt_", "chain prefix"},
		{"empty ipset", "MT_", "", "ipset prefix"},
		{"short ipset", "MT_", "mt", "ipset prefix"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			helper, err := New(tt.chain, tt.ipset, true, true, 0)
			if tt.wantError != "" {
				if helper != nil || err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("expected %s error, got helper=%v err=%v", tt.wantError, helper, err)
				}
			} else if err != nil || helper == nil {
				t.Fatalf("valid prefixes rejected: %v", err)
			}
		})
	}
}
