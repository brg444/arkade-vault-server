package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type mountedHandler struct{}

func (*mountedHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func TestHostMountsHandlerUnchangedAndOwnsLifecycle(t *testing.T) {
	registry, err := Compile(testDefinition("host"))
	if err != nil {
		t.Fatal(err)
	}
	handler := &mountedHandler{}
	var readyCalls, closeCalls atomic.Int32
	host, err := Open(registry, "profile-host", Mount{
		Handler: handler,
		Readiness: func(context.Context) error {
			readyCalls.Add(1)
			return nil
		},
		Shutdown: func() error {
			closeCalls.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if host.Handler() != handler {
		t.Fatal("host wrapped or replaced the mounted HTTP handler")
	}
	recorder := httptest.NewRecorder()
	host.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/host", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("mounted handler status = %d", recorder.Code)
	}
	if err := host.Ready(context.Background()); err != nil || readyCalls.Load() != 1 {
		t.Fatalf("host readiness = %v, calls %d", err, readyCalls.Load())
	}
	if host.Profile().ID() != "profile-host" || host.State() != StateOpen {
		t.Fatalf("mounted host = %q %q", host.Profile().ID(), host.State())
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if closeCalls.Load() != 1 || host.State() != StateClosed {
		t.Fatalf("host close calls/state = %d/%q", closeCalls.Load(), host.State())
	}
	if err := host.Ready(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed readiness = %v", err)
	}
}

func TestHostRequiresCompiledProfileAndLifecycle(t *testing.T) {
	registry, err := Compile(testDefinition("host"))
	if err != nil {
		t.Fatal(err)
	}
	valid := Mount{
		Handler:   &mountedHandler{},
		Readiness: func(context.Context) error { return nil },
		Shutdown:  func() error { return nil },
	}
	if _, err := Open(registry, "not-compiled", valid); err == nil {
		t.Fatal("uncompiled profile mounted")
	}
	missingHandler := valid
	missingHandler.Handler = nil
	if _, err := Open(registry, "profile-host", missingHandler); err == nil {
		t.Fatal("nil handler mounted")
	}
	missingReadiness := valid
	missingReadiness.Readiness = nil
	if _, err := Open(registry, "profile-host", missingReadiness); err == nil {
		t.Fatal("nil readiness mounted")
	}
	missingShutdown := valid
	missingShutdown.Shutdown = nil
	if _, err := Open(registry, "profile-host", missingShutdown); err == nil {
		t.Fatal("nil shutdown mounted")
	}
}

func TestHostMultipleCompiledProfilesShareOneLifecycle(t *testing.T) {
	registry, err := Compile(testDefinition("first"), testDefinition("second"))
	if err != nil {
		t.Fatal(err)
	}
	var closes atomic.Int32
	mount := Mount{Handler: &mountedHandler{}, Readiness: func(context.Context) error { return nil }, Shutdown: func() error { closes.Add(1); return nil }}
	for _, selection := range [][]string{nil, {"profile-first", "profile-first"}, {"profile-first", "not-compiled"}} {
		if _, err := OpenProfiles(registry, selection, mount); err == nil {
			t.Fatalf("accepted invalid selection %v", selection)
		}
	}
	host, err := OpenProfiles(registry, []string{"profile-first", "profile-second"}, mount)
	if err != nil {
		t.Fatal(err)
	}
	profiles := host.Profiles()
	if len(profiles) != 2 {
		t.Fatal("compiled selection missing")
	}
	profiles[0] = Profile{}
	if host.Profiles()[0].ID() != "profile-first" {
		t.Fatal("profile selection is mutable")
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if closes.Load() != 1 {
		t.Fatal("ledger closed more than once")
	}
}
