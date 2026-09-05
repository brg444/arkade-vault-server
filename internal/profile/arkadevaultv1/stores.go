package arkadevaultv1

import (
	"context"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
)

// IdentityStore is the authenticated enrollment and credential persistence
// needed by arkade-vault-v1. It deliberately exposes no generic key/value
// operations.
type IdentityStore interface {
	RequireIntegrityKey([]byte) error
	SchemaVersion() (int, error)
	GetInvite([]byte) (*policy.Invite, error)
	IssueEnrollmentSession([]byte, time.Time) (time.Time, error)
	ReservePendingEnrollment(policy.PendingEnrollment) (*policy.PendingEnrollment, error)
	GetPendingByHandle(string) (*policy.PendingEnrollment, error)
	CreateVault(policy.CreateVaultInput) error
	ListVaultIDs() ([]string, error)
	LoadVerifiedVault(string, []byte) (*policy.VaultRecord, *policy.VaultCredential, error)
	GetVaultEnvelope(string) (*policy.CredentialEnvelope, error)
	StoreVaultEnvelopeIfAbsent(string, policy.CredentialEnvelope) error
	ReplaceVaultEnvelope(string, policy.CredentialEnvelope, policy.CredentialEnvelope) error
	AdvanceSignCount(string, []byte, uint32) error
}

// AllowanceStore owns the atomic allowance/outflow reservation. The reserve
// call creates the VTXO operation and advances the independent policy sequence
// in the same SQLite transaction as the allowance check.
type AllowanceStore interface {
	PeriodStart() string
	SpentInPeriod(context.Context, string, string) (int64, error)
	ReserveVtxoOperation(context.Context, policy.VtxoOperation, []policy.VtxoOperationInput, int64) error
}

// VtxoOperationStore persists only the lifecycle of an already-reserved VTXO
// operation. Creation stays on AllowanceStore to preserve atomic accounting.
type VtxoOperationStore interface {
	NowUTC() time.Time
	GetVtxoOperation(context.Context, string) (policy.VtxoOperation, error)
	GetVtxoOperationInputs(context.Context, string) ([]policy.VtxoOperationInput, error)
	TransitionVtxoOperation(context.Context, string, policy.VtxoOperation) (policy.VtxoOperation, bool, error)
	CommitSignedVtxoOperation(context.Context, policy.VtxoOperation, []byte, uint32) (policy.VtxoOperation, bool, error)
	VerifySignedVtxoReplay(context.Context, string, string, []byte, uint32) error
}

// RecoveryOperationStore is the replay-safe Savings recovery operation store.
type RecoveryOperationStore interface {
	ApplyRecoveryReplay(policy.RecoverySession) (policy.ReplayAction, *policy.RecoverySession, error)
}

// MapStore persists only the typed Recovery Kit map document.
type MapStore interface {
	GetVaultMap(string) (*policy.VaultMap, error)
	PutVaultMap(policy.VaultMap) error
}

// VaultBoardStore is the authenticated lifecycle boundary for boarding. It
// exposes neither allowance mutation nor generic storage.
type VaultBoardStore interface {
	CreateVaultWithBoard(policy.CreateVaultInput, policy.VaultBoardEnrollment) error
	GetVaultBoardEnrollment(string) (*policy.VaultBoardEnrollment, error)
	GetCurrentVaultBoardAttempt(context.Context, string) (*policy.VaultBoardAttemptSnapshot, error)
	BeginVaultBoardAttempt(context.Context, policy.VaultBoardOperation, policy.VaultBoardRegisterRequest, policy.VaultBoardChainState) (*policy.VaultBoardOperation, *policy.VaultBoardAuthorization, bool, error)
	AppendVaultBoardAuthorizationAndDispatch(context.Context, policy.VaultBoardAuthorization, policy.VaultBoardChainState) (*policy.VaultBoardAuthorization, *policy.VaultBoardDispatch, bool, error)
	AppendVaultBoardDispatch(context.Context, policy.VaultBoardDispatch, policy.VaultBoardChainState) (*policy.VaultBoardDispatch, bool, error)
	AppendVaultBoardSubmission(context.Context, policy.VaultBoardSubmission) (*policy.VaultBoardSubmission, bool, error)
}

// LightRenewalStore shares the ledger's atomic allowance and sequence boundary.
type LightRenewalStore interface {
	ReserveLightRenewal(context.Context, policy.LightRenewalOperation, int64) (*policy.LightRenewalSnapshot, error)
	GetLightRenewal(context.Context, string) (*policy.LightRenewalSnapshot, error)
	AppendLightRenewalEvent(context.Context, policy.LightRenewalEvent, []byte, uint32) (policy.LightRenewalEvent, bool, error)
}

// Stores is the complete persistence capability set compiled into the
// arkade-vault-v1 profile.
type Stores struct {
	Identity           IdentityStore
	Allowance          AllowanceStore
	VtxoOperations     VtxoOperationStore
	RecoveryOperations RecoveryOperationStore
	Maps               MapStore
	VaultBoard         VaultBoardStore
	LightRenewal       LightRenewalStore
}

func (s Stores) Validate() error {
	switch {
	case s.Identity == nil:
		return fmt.Errorf("arkade-vault-v1 identity store required")
	case s.Allowance == nil:
		return fmt.Errorf("arkade-vault-v1 allowance store required")
	case s.VtxoOperations == nil:
		return fmt.Errorf("arkade-vault-v1 VTXO operation store required")
	case s.RecoveryOperations == nil:
		return fmt.Errorf("arkade-vault-v1 recovery operation store required")
	case s.Maps == nil:
		return fmt.Errorf("arkade-vault-v1 map store required")
	case s.LightRenewal == nil:
		return fmt.Errorf("Light renewal store required")
	case s.VaultBoard == nil:
		return fmt.Errorf("arkade-vault-v1 Vault Board store required")
	default:
		return nil
	}
}

// StoresFromLedger narrows one authenticated SQLite ledger into the five
// profile capabilities. Every interface intentionally points at the same
// object, preserving the physical database and transaction boundaries.
func StoresFromLedger(ledger *policy.Ledger) (Stores, error) {
	if ledger == nil {
		return Stores{}, fmt.Errorf("arkade-vault-v1 ledger required")
	}
	return Stores{
		Identity:           ledger,
		Allowance:          ledger,
		VtxoOperations:     ledger,
		RecoveryOperations: ledger,
		Maps:               ledger,
		VaultBoard:         ledger,
		LightRenewal:       ledger,
	}, nil
}
