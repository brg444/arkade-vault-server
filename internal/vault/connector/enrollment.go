package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

const EnrollmentSchema = "arkade-vault/connector-enrollment-v1"

// EnrollmentDigest commits the complete rebuilt contract and hardware origin.
// The existing enrollment wire format does not accept this schema yet.
func EnrollmentDigest(in savings.FamilyInput, origin KeyOrigin) (string, error) {
	kind, err := origin.Kind()
	if err != nil {
		return "", err
	}
	f, err := BuildFamily(in, kind)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(origin.PublicKey, in.Hardware.SerializeCompressed()) {
		return "", fmt.Errorf("hardware origin mismatch")
	}
	coin := uint32(0x80000000)
	if in.Network == "mutinynet" {
		coin++
	}
	p := origin.Path
	if p[0] == kind.Purpose() && p[1] != coin {
		return "", fmt.Errorf("hardware origin network or path mismatch")
	}
	path := make([]string, len(p))
	for i, n := range p {
		path[i] = strconv.FormatUint(uint64(n), 10)
	}
	policy, err := program.SpendingPolicyDigestHexFor(in.Network, in.SpendingPolicy)
	if err != nil {
		return "", err
	}
	recovery := ""
	if in.Recovery != nil {
		recovery = hex.EncodeToString(in.Recovery.SerializeCompressed())
	}
	fields := []string{EnrollmentSchema, Template, in.VaultID, in.Network, in.ProtectionTier,
		hex.EncodeToString(in.Phone.SerializeCompressed()), hex.EncodeToString(in.Hardware.SerializeCompressed()), recovery,
		hex.EncodeToString(in.PhoneDirectP256), hex.EncodeToString(in.VaultCosignerBase.SerializeCompressed()), hex.EncodeToString(in.ArkadeCosignerBase.SerializeCompressed()), policy,
		hex.EncodeToString(f.Program), hex.EncodeToString(f.Recovery.Savings.PkScript), hex.EncodeToString(f.Rules.ConnectorScript), fmt.Sprintf("%08x", origin.Fingerprint), strings.Join(path, "/")}
	roles := []string{"phone", "hardware"}
	if in.Recovery != nil {
		roles = append(roles, "recovery")
	}
	for _, role := range roles {
		k := savings.FamilyKey(role)
		fields = append(fields, role, hex.EncodeToString(f.Recovery.Pending[k].PkScript), hex.EncodeToString(f.Recovery.Quarantine[k].PkScript), hex.EncodeToString(f.Recovery.InitiateAuth[k]), hex.EncodeToString(f.Recovery.ClawbackAuth[k]))
	}
	h := sha256.New()
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
