package main

import (
	"os"
	"testing"
)

func TestInviteOnlyConfigDefaultsClosedAndRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "true"} {
		got, err := parseInviteOnly(value)
		if err != nil || !got {
			t.Fatalf("%q must require invitations", value)
		}
	}
	if got, err := parseInviteOnly("false"); err != nil || got {
		t.Fatal("false must enable open enrollment")
	}
	if got, err := parseInviteOnly("typo"); err == nil || !got {
		t.Fatal("invalid configuration must fail closed")
	}
}

func TestClearGatewaySecretEnv(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "startup-only-secret")
	if err := clearGatewaySecretEnv(); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("VAULT_GATEWAY_SECRET"); ok {
		t.Fatal("gateway secret remained in the process environment")
	}
}

func TestParseLightEnabled(t *testing.T) {
	for _, value := range []string{"", "false"} {
		enabled, err := parseLightEnabled(value)
		if err != nil || enabled {
			t.Fatalf("default enablement for %q", value)
		}
	}
	if enabled, err := parseLightEnabled("true"); err != nil || !enabled {
		t.Fatal("explicit enablement rejected")
	}
	for _, value := range []string{"1", "TRUE", " false ", "yes"} {
		if _, err := parseLightEnabled(value); err == nil {
			t.Fatalf("invalid rollout value %q", value)
		}
	}
}
