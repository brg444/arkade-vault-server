package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type lightEnrolledFixture struct {
	env     *env
	token   string
	start   *EnrollStartResponse
	request LightEnrollFinishRequest
}

func lightEnrollmentFixture(t *testing.T, open bool) (*Service, string, *EnrollStartResponse, LightEnrollFinishRequest, *btcec.PrivateKey) {
	f := newLightEnrollmentFixture(t, open)
	return f.env.svc, f.token, f.start, f.request, f.env.hot
}
func newLightEnrollmentFixture(t *testing.T, open bool) lightEnrolledFixture {
	t.Helper()
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "light.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	svc := enrollService(t, ledger)
	svc.LightEnabled = true
	svc.OpenEnrollment = open
	svc.ArkResolver = stubArkResolver{signer: mustDecode(t, "03301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a")}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32))
	if open {
		session, e := svc.IssueEnrollmentSession()
		if e != nil {
			t.Fatal(e)
		}
		token = session.Token
	} else {
		hash, e := HashEnrollmentToken(token)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC()
		if e := ledger.PutInvite(hash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
	}
	p, err := light.DefaultPolicy(svc.runtimeConfig().Network)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := light.PolicyDigest(svc.runtimeConfig().Network, p)
	if err != nil {
		t.Fatal(err)
	}
	selected := LightEnrollStartRequest{SpendingPolicy: p, SpendingPolicyDigest: digest}
	start, err := svc.StartLightEnrollment(token, selected)
	if err != nil {
		t.Fatal(err)
	}
	pass, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ceremony := attestedFinish(t, svc, start, pass, []byte("light-credential"), RegisterRequest{})
	req := LightEnrollFinishRequest{Handle: start.Handle, VaultID: start.VaultID, UserHandle: start.UserID,
		ClientDataJSON: ceremony.ClientDataJSON, AuthenticatorData: ceremony.AuthenticatorData, AttestationObject: ceremony.AttestationObject,
		CredentialID: ceremony.CredentialID, WebAuthnP256: ceremony.WebAuthnP256, PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(direct)),
		OwnerPub: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())), LightEnrollStartRequest: selected}
	proposed, err := svc.ProposeLightEnrollment(token, req)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = proposed.DescriptorHash
	return lightEnrolledFixture{env: &env{svc: svc, ledger: ledger, hot: owner, p256: pass, direct: direct, credID: []byte("light-credential")}, token: token, start: start, request: req}
}

func TestLightEnrollmentAdmissionRestartAndReplay(t *testing.T) {
	for _, open := range []bool{false, true} {
		t.Run(map[bool]string{false: "invite", true: "open"}[open], func(t *testing.T) {
			svc, token, start, req, _ := lightEnrollmentFixture(t, open)
			repeat, err := svc.StartLightEnrollment(token, req.LightEnrollStartRequest)
			if err != nil || repeat.VaultID != start.VaultID || repeat.Challenge != start.Challenge {
				t.Fatalf("start replay: %v", err)
			}
			// Admission changes cannot revoke an already-issued session.
			svc.OpenEnrollment = false
			st, err := svc.FinishLightEnrollment(context.Background(), token, req)
			if err != nil {
				t.Fatal(err)
			}
			if st.LightDescriptor == nil || st.ProtectionTier != "light" || st.TemplateVersion != light.Profile || st.SavingsAddr != "" || st.ExternalOwnerWalletPub != "" || st.VtxoBoardingActive || st.VtxoDelegatePub != "" || st.SpendingArkAddress == "" {
				t.Fatalf("wrong Light status: %+v", st)
			}
			before := st.SpendingArkScript
			if err := svc.LoadVaults(); err != nil {
				t.Fatal(err)
			}
			after, err := svc.StatusFor(context.Background(), start.VaultID)
			if err != nil || after.SpendingArkScript != before {
				t.Fatalf("restart changed contract: %v", err)
			}
			if _, err := svc.FinishLightEnrollment(context.Background(), token, req); err != nil {
				t.Fatalf("lost-response replay: %v", err)
			}
			forged := req
			forged.DescriptorHash = string(bytes.Repeat([]byte{'0'}, 64))
			if _, err := svc.FinishLightEnrollment(context.Background(), token, forged); err == nil {
				t.Fatal("accepted changed descriptor replay")
			}
			forged = req
			forged.PhoneDirectP256 = req.WebAuthnP256
			if _, err := svc.FinishLightEnrollment(context.Background(), token, forged); err == nil {
				t.Fatal("accepted passkey as direct key")
			}
			if _, err := svc.StartEnrollment(token, defaultEnrollStartRequest(t)); err == nil {
				t.Fatal("consumed Light token enrolled Standard")
			}
			_, snap, rec, err := svc.resolveSpendVaultRecord(start.VaultID)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Savings != nil || snap.Board != nil || rec.TemplateVersion != light.Profile {
				t.Fatal("Light entered Savings or boarding")
			}
		})
	}
}

func TestLightEnrollmentRejectsCeremonyAndPolicySubstitution(t *testing.T) {
	for _, field := range []string{"origin", "credential", "policy", "descriptor", "vault", "handle", "token"} {
		t.Run(field, func(t *testing.T) {
			svc, token, _, req, _ := lightEnrollmentFixture(t, true)
			switch field {
			case "origin":
				req.ClientDataJSON = hex.EncodeToString([]byte(`{"type":"webauthn.create","origin":"https://evil.example"}`))
			case "credential":
				req.CredentialID = "1234"
			case "policy":
				req.SpendingPolicy.TxRecipientCapSats++
			case "descriptor":
				req.DescriptorHash = ""
			case "vault":
				req.VaultID = string(bytes.Repeat([]byte{'a'}, 64))
			case "handle":
				req.UserHandle = "1234"
			case "token":
				token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x45}, 32))
			}
			if _, err := svc.FinishLightEnrollment(context.Background(), token, req); err == nil {
				t.Fatal("accepted substituted enrollment")
			}
		})
	}
}

func TestLightRolloutFlagLeavesExistingWalletsAndAdmissionIndependent(t *testing.T) {
	svc, token, start, req, _ := lightEnrollmentFixture(t, true)
	svc.LightEnabled = false
	status, err := svc.PublicStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.EnrollmentMode != "open" {
		t.Fatal("Light rollout changed invite policy")
	}
	for _, setup := range status.SupportedSetups {
		if setup == "light" {
			t.Fatal("disabled Light advertised")
		}
	}
	if _, err := svc.StartLightEnrollment(token, req.LightEnrollStartRequest); err == nil {
		t.Fatal("disabled rollout accepted new Light start")
	}
	// An already-started enrollment can finish without changing its descriptor.
	if _, err := svc.FinishLightEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	if err := svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StatusFor(context.Background(), start.VaultID); err != nil {
		t.Fatal(err)
	}
}

func TestLightExpiredSetupCanRestartButCompletedSetupStillReplays(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unfinished", true: "completed"}[completed], func(t *testing.T) {
			f := newLightEnrollmentFixture(t, true)
			s := f.env.svc
			if completed {
				if _, err := s.FinishLightEnrollment(context.Background(), f.token, f.request); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC().Add(pendingEnrollmentTTL + time.Minute)
			s.EnrollmentNow = func() time.Time { return now }
			result, err := s.FinishLightEnrollment(context.Background(), f.token, f.request)
			if completed {
				if err != nil || result.VaultID != f.start.VaultID {
					t.Fatalf("completed enrollment was treated as expired: %v", err)
				}
			} else {
				if !errors.Is(err, errLightEnrollmentExpired) {
					t.Fatalf("expiry not distinguished: %v", err)
				}
				raw, _ := json.Marshal(f.request)
				req := httptest.NewRequest(http.MethodPost, "/v1/light/enroll/finish", bytes.NewReader(raw))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", s.Deployment.ClientOrigin)
				req.Header.Set(EnrollmentTokenHeader, f.token)
				res := httptest.NewRecorder()
				mux := http.NewServeMux()
				attachLightEnrollmentRoutes(mux, s, s.Deployment.ClientOrigin)
				mux.ServeHTTP(res, req)
				if res.Code != http.StatusGone || res.Body.String() != "{\"error\":\"light_enrollment_expired\"}\n" {
					t.Fatalf("expiry HTTP response = %d %s", res.Code, res.Body.String())
				}
				replacement, err := s.StartLightEnrollment(f.token, f.request.LightEnrollStartRequest)
				if err != nil || replacement.VaultID == f.start.VaultID {
					t.Fatalf("fresh ceremony unavailable: %v", err)
				}
			}
		})
	}
}
