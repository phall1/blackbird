// Package localsecurity implements the credential-vault and cryptographic
// boundary for Blackbird's local pairing profile.
package localsecurity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/lexfrei/keychain"
)

const (
	pairingExporterLabel = "EXPORTER-Blackbird-Pair-v1"
	sessionExporterLabel = "EXPORTER-Blackbird-Session-v1"
	transcriptDomain     = "blackbird-pairing-transcript/v1"
	bindingSize          = 32
	credentialService    = "com.phall1.blackbird.credentials.v1"
	credentialIDMaxBytes = 128
)

var (
	ErrInvalidKeyMaterial  = errors.New("invalid Ed25519 key material")
	ErrInvalidCertificate  = errors.New("invalid local certificate")
	ErrInvalidPin          = errors.New("invalid peer SPKI pin")
	ErrPeerVerification    = errors.New("pinned TLS peer verification failed")
	ErrExporter            = errors.New("TLS exporter unavailable")
	ErrInvalidTranscript   = errors.New("invalid pairing transcript")
	ErrInvalidProof        = errors.New("invalid pairing proof")
	ErrInvalidCredential   = errors.New("invalid credential reference")
	ErrCredentialExists    = errors.New("credential already exists")
	ErrCredentialNotFound  = errors.New("credential not found")
	ErrVaultUnavailable    = errors.New("OS credential vault unavailable")
	ErrCredentialDestroyed = errors.New("credential key material destroyed")
)

// CredentialKind identifies a long-lived local Ed25519 credential class.
type CredentialKind string

const (
	InstallationCredential CredentialKind = "installation"
	DeviceCredential       CredentialKind = "device"
)

// CredentialReference is an opaque, non-secret handle suitable for persisted
// metadata. It never contains seed material.
type CredentialReference struct {
	kind       CredentialKind
	identifier string
}

// NewCredentialReference validates an application identifier and builds a
// handle for an installation or device credential.
func NewCredentialReference(kind CredentialKind, identifier string) (CredentialReference, error) {
	if kind != InstallationCredential && kind != DeviceCredential || !validCredentialIdentifier(identifier) {
		return CredentialReference{}, ErrInvalidCredential
	}
	return CredentialReference{kind: kind, identifier: identifier}, nil
}

func InstallationCredentialReference(identifier string) (CredentialReference, error) {
	return NewCredentialReference(InstallationCredential, identifier)
}

func DeviceCredentialReference(identifier string) (CredentialReference, error) {
	return NewCredentialReference(DeviceCredential, identifier)
}

func (reference CredentialReference) Kind() CredentialKind { return reference.kind }

func (reference CredentialReference) String() string {
	if reference.kind == "" || reference.identifier == "" {
		return ""
	}
	return "credential:" + string(reference.kind) + ":" + reference.identifier
}

func (reference CredentialReference) account() string {
	return "ed25519-seed/v1/" + string(reference.kind) + "/" + reference.identifier
}

// SecretStore is the injectable byte-oriented vault surface. Implementations
// must not log, persist outside a protected vault, or retain caller buffers.
type SecretStore interface {
	Set(service, account string, secret []byte) error
	Get(service, account string) ([]byte, error)
	Delete(service, account string) error
}

type osSecretStore struct {
	keychain *keychain.Keychain
}

func (store osSecretStore) Set(service, account string, secret []byte) error {
	return store.keychain.Set(service, account, secret)
}

func (store osSecretStore) Get(service, account string) ([]byte, error) {
	return store.keychain.Get(service, account)
}

func (store osSecretStore) Delete(service, account string) error {
	return store.keychain.Delete(service, account)
}

// CredentialVault owns local Ed25519 seed lifecycle operations. Operations are
// serialized so create and rotate semantics are deterministic within a process.
type CredentialVault struct {
	mu     sync.Mutex
	store  SecretStore
	random io.Reader
}

// NewOSCredentialVault uses the silent, native, CGo-free platform keychain.
// It deliberately does not enable the macOS CLI fallback because that fallback
// places the secret in a process argument.
func NewOSCredentialVault() *CredentialVault {
	return NewCredentialVault(osSecretStore{keychain: keychain.New()}, rand.Reader)
}

// NewCredentialVault injects a vault and entropy source. Supplying nil causes
// lifecycle calls to fail closed with ErrVaultUnavailable.
func NewCredentialVault(store SecretStore, random io.Reader) *CredentialVault {
	return &CredentialVault{store: store, random: random}
}

// Ed25519Credential keeps a loaded seed inside this boundary and implements
// crypto.Signer. Call Destroy as soon as the signing lifetime ends. Go cannot
// guarantee zeroization of copies made by the runtime or operating system.
type Ed25519Credential struct {
	mu        sync.RWMutex
	reference CredentialReference
	seed      [ed25519.SeedSize]byte
	destroyed bool
}

func (credential *Ed25519Credential) Reference() CredentialReference {
	if credential == nil {
		return CredentialReference{}
	}
	return credential.reference
}

func (credential *Ed25519Credential) String() string   { return "[REDACTED Ed25519 credential]" }
func (credential *Ed25519Credential) GoString() string { return credential.String() }

func (credential *Ed25519Credential) Public() crypto.PublicKey {
	publicKey, err := credential.PublicKey()
	if err != nil {
		return nil
	}
	return publicKey
}

func (credential *Ed25519Credential) PublicKey() (ed25519.PublicKey, error) {
	if credential == nil {
		return nil, ErrCredentialDestroyed
	}
	credential.mu.RLock()
	defer credential.mu.RUnlock()
	if credential.destroyed {
		return nil, ErrCredentialDestroyed
	}
	privateKey := ed25519.NewKeyFromSeed(credential.seed[:])
	defer clear(privateKey)
	return append(ed25519.PublicKey(nil), privateKey[ed25519.SeedSize:]...), nil
}

func (credential *Ed25519Credential) Sign(_ io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	if credential == nil {
		return nil, ErrCredentialDestroyed
	}
	if options != nil && options.HashFunc() != crypto.Hash(0) {
		return nil, ErrInvalidKeyMaterial
	}
	credential.mu.RLock()
	defer credential.mu.RUnlock()
	if credential.destroyed {
		return nil, ErrCredentialDestroyed
	}
	privateKey := ed25519.NewKeyFromSeed(credential.seed[:])
	defer clear(privateKey)
	return ed25519.Sign(privateKey, message), nil
}

func (credential *Ed25519Credential) NewCertificate(validity CertificateValidity) (tls.Certificate, SPKIPin, error) {
	publicKey, err := credential.PublicKey()
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, err
	}
	return newCertificate(publicKey, credential, validity)
}

func (credential *Ed25519Credential) Destroy() {
	if credential == nil {
		return
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	clear(credential.seed[:])
	credential.destroyed = true
}

func (vault *CredentialVault) CreateCredential(reference CredentialReference) (*Ed25519Credential, error) {
	return vault.create(reference, false)
}

func (vault *CredentialVault) LoadCredential(reference CredentialReference) (*Ed25519Credential, error) {
	if err := validateCredentialReference(reference); err != nil {
		return nil, err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	return vault.load(reference)
}

func (vault *CredentialVault) RotateCredential(reference CredentialReference) (*Ed25519Credential, error) {
	return vault.create(reference, true)
}

func (vault *CredentialVault) DeleteCredential(reference CredentialReference) error {
	if err := validateCredentialReference(reference); err != nil {
		return err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	material, err := vault.get(reference)
	if err != nil {
		return err
	}
	clear(material)
	if err := vault.store.Delete(credentialService, reference.account()); err != nil {
		return vaultError("delete", err)
	}
	return nil
}

func (vault *CredentialVault) create(reference CredentialReference, rotate bool) (*Ed25519Credential, error) {
	if err := validateCredentialReference(reference); err != nil {
		return nil, err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	material, err := vault.get(reference)
	switch {
	case err == nil:
		clear(material)
		if !rotate {
			return nil, ErrCredentialExists
		}
	case errors.Is(err, ErrCredentialNotFound):
		if rotate {
			return nil, err
		}
	default:
		return nil, err
	}
	if vault.random == nil {
		return nil, fmt.Errorf("%w: entropy source is not configured", ErrVaultUnavailable)
	}
	var seed [ed25519.SeedSize]byte
	if _, err := io.ReadFull(vault.random, seed[:]); err != nil {
		clear(seed[:])
		return nil, fmt.Errorf("%w: generate Ed25519 seed", ErrVaultUnavailable)
	}
	if err := vault.store.Set(credentialService, reference.account(), seed[:]); err != nil {
		clear(seed[:])
		return nil, vaultError("store", err)
	}
	credential := &Ed25519Credential{reference: reference, seed: seed}
	clear(seed[:])
	return credential, nil
}

func (vault *CredentialVault) load(reference CredentialReference) (*Ed25519Credential, error) {
	material, err := vault.get(reference)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	if len(material) != ed25519.SeedSize {
		return nil, ErrInvalidKeyMaterial
	}
	credential := &Ed25519Credential{reference: reference}
	copy(credential.seed[:], material)
	return credential, nil
}

func (vault *CredentialVault) get(reference CredentialReference) ([]byte, error) {
	if vault == nil || vault.store == nil {
		return nil, fmt.Errorf("%w: no credential store is configured", ErrVaultUnavailable)
	}
	material, err := vault.store.Get(credentialService, reference.account())
	if err != nil {
		clear(material)
		return nil, vaultError("read", err)
	}
	return material, nil
}

func vaultError(operation string, err error) error {
	if errors.Is(err, keychain.ErrNotFound) || errors.Is(err, ErrCredentialNotFound) {
		return ErrCredentialNotFound
	}
	return fmt.Errorf("%w: cannot %s credential: %w", ErrVaultUnavailable, operation, err)
}

func validateCredentialReference(reference CredentialReference) error {
	if reference.kind != InstallationCredential && reference.kind != DeviceCredential ||
		!validCredentialIdentifier(reference.identifier) {
		return ErrInvalidCredential
	}
	return nil
}

func validCredentialIdentifier(identifier string) bool {
	if identifier == "" || len(identifier) > credentialIDMaxBytes || strings.TrimSpace(identifier) != identifier {
		return false
	}
	for _, value := range identifier {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' || value == '-' || value == '_' || value == '.' {
			continue
		}
		return false
	}
	return true
}

// SPKIPin is SHA-256 over the canonical DER SubjectPublicKeyInfo encoding.
type SPKIPin [sha256.Size]byte

// Binding is a fixed-size tls-exporter channel binding.
type Binding [bindingSize]byte

// TranscriptHash is the SHA-256 digest of an already JCS-canonical transcript.
type TranscriptHash [sha256.Size]byte

// CertificateValidity fixes the identity certificate's validity window.
type CertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// NewCertificate creates a self-signed Ed25519 client/server certificate from
// an Ed25519 seed or private key. The caller remains responsible for keeping
// the supplied key material in a credential vault.
func NewCertificate(keyMaterial []byte, validity CertificateValidity) (tls.Certificate, SPKIPin, error) {
	privateKey, err := privateKeyFromMaterial(keyMaterial)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return newCertificate(publicKey, privateKey, validity)
}

func newCertificate(
	publicKey ed25519.PublicKey,
	privateKey crypto.Signer,
	validity CertificateValidity,
) (tls.Certificate, SPKIPin, error) {
	pin, err := PinPublicKey(publicKey)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, err
	}
	if validity.NotBefore.IsZero() || !validity.NotAfter.After(validity.NotBefore) {
		return tls.Certificate{}, SPKIPin{}, ErrInvalidCertificate
	}

	serialBytes := append([]byte(nil), pin[:20]...)
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Blackbird local peer"},
		NotBefore:    validity.NotBefore.UTC(),
		NotAfter:     validity.NotAfter.UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, fmt.Errorf("%w: create certificate", ErrInvalidCertificate)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, fmt.Errorf("%w: parse certificate", ErrInvalidCertificate)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, pin, nil
}

// PinPublicKey returns the canonical SHA-256 SPKI pin for an Ed25519 key.
func PinPublicKey(publicKey ed25519.PublicKey) (SPKIPin, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return SPKIPin{}, ErrInvalidKeyMaterial
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return SPKIPin{}, fmt.Errorf("%w: marshal SPKI", ErrInvalidKeyMaterial)
	}
	return sha256.Sum256(spki), nil
}

// PairingClientTLSConfig creates the first-contact TLS client. The daemon is
// pinned from the invitation; the not-yet-trusted client key is authenticated
// by the signed pairing transcript rather than a client certificate.
// InsecureSkipVerify is intentional: ambient roots and DNS identity are
// replaced by VerifyConnection's certificate, key-usage, and SPKI checks.
func PairingClientTLSConfig(serverPins ...SPKIPin) (*tls.Config, error) {
	if err := validatePins(serverPins); err != nil {
		return nil, err
	}
	pins := append([]SPKIPin(nil), serverPins...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Verification is pin-based below; no ambient roots.
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPinnedPeer(state, pins, x509.ExtKeyUsageServerAuth, time.Now())
		},
	}, nil
}

// PairingServerTLSConfig creates the daemon side of first-contact TLS. Client
// authentication is completed by the exporter-bound transcript protocol.
func PairingServerTLSConfig(certificate tls.Certificate) (*tls.Config, error) {
	if err := validateLocalCertificate(certificate); err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert,
	}, nil
}

// PairedClientTLSConfig creates a TLS 1.3-only mTLS client with explicit server pins.
func PairedClientTLSConfig(certificate tls.Certificate, serverPins ...SPKIPin) (*tls.Config, error) {
	if err := validateLocalCertificate(certificate); err != nil {
		return nil, err
	}
	config, err := PairingClientTLSConfig(serverPins...)
	if err != nil {
		return nil, err
	}
	config.Certificates = []tls.Certificate{certificate}
	return config, nil
}

// PairedServerTLSConfig creates a TLS 1.3-only mTLS server with explicit client pins.
// RequireAnyClientCert obtains a certificate without consulting ambient roots;
// VerifyConnection performs the complete peer check.
func PairedServerTLSConfig(certificate tls.Certificate, clientPins ...SPKIPin) (*tls.Config, error) {
	if err := validateLocalCertificate(certificate); err != nil {
		return nil, err
	}
	if err := validatePins(clientPins); err != nil {
		return nil, err
	}
	pins := append([]SPKIPin(nil), clientPins...)
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPinnedPeer(state, pins, x509.ExtKeyUsageClientAuth, time.Now())
		},
	}, nil
}

// PairingBinding derives the reviewed pairing channel-binding value.
func PairingBinding(state tls.ConnectionState) (Binding, error) {
	return exportBinding(state, pairingExporterLabel)
}

// SessionBinding derives the reviewed paired-session channel-binding value.
func SessionBinding(state tls.ConnectionState) (Binding, error) {
	return exportBinding(state, sessionExporterLabel)
}

// HashTranscript hashes an already validated RFC 8785 JCS encoding. This
// boundary intentionally does not accept or normalize noncanonical JSON.
func HashTranscript(canonicalJCS []byte) (TranscriptHash, error) {
	if len(canonicalJCS) == 0 {
		return TranscriptHash{}, ErrInvalidTranscript
	}
	return sha256.Sum256(canonicalJCS), nil
}

// SignTranscript signs the transcript digest under the reviewed domain.
func SignTranscript(privateKey ed25519.PrivateKey, transcript TranscriptHash) ([]byte, error) {
	if !validPrivateKey(privateKey) || transcript == (TranscriptHash{}) {
		return nil, ErrInvalidTranscript
	}
	return ed25519.Sign(privateKey, transcriptMessage(transcript)), nil
}

// VerifyTranscript verifies a transcript signature and its domain binding.
func VerifyTranscript(publicKey ed25519.PublicKey, transcript TranscriptHash, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || transcript == (TranscriptHash{}) ||
		len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, transcriptMessage(transcript), signature) {
		return ErrInvalidTranscript
	}
	return nil
}

// PairingProof computes HMAC-SHA-256(secret, exporter || transcript_hash).
func PairingProof(invitationSecret []byte, binding Binding, transcript TranscriptHash) ([sha256.Size]byte, error) {
	if len(invitationSecret) != 32 || binding == (Binding{}) || transcript == (TranscriptHash{}) {
		return [sha256.Size]byte{}, ErrInvalidProof
	}
	mac := hmac.New(sha256.New, invitationSecret)
	_, _ = mac.Write(binding[:])
	_, _ = mac.Write(transcript[:])
	var proof [sha256.Size]byte
	copy(proof[:], mac.Sum(nil))
	return proof, nil
}

// VerifyPairingProof compares a presented proof without exposing it in errors.
func VerifyPairingProof(invitationSecret []byte, binding Binding, transcript TranscriptHash, proof []byte) error {
	want, err := PairingProof(invitationSecret, binding, transcript)
	if err != nil || len(proof) != sha256.Size || subtle.ConstantTimeCompare(want[:], proof) != 1 {
		return ErrInvalidProof
	}
	return nil
}

func privateKeyFromMaterial(material []byte) (ed25519.PrivateKey, error) {
	var privateKey ed25519.PrivateKey
	switch len(material) {
	case ed25519.SeedSize:
		seed := append([]byte(nil), material...)
		privateKey = ed25519.NewKeyFromSeed(seed)
		clear(seed)
	case ed25519.PrivateKeySize:
		privateKey = append(ed25519.PrivateKey(nil), material...)
		derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(privateKey, derived) != 1 {
			clear(privateKey)
			return nil, ErrInvalidKeyMaterial
		}
	default:
		return nil, ErrInvalidKeyMaterial
	}
	return privateKey, nil
}

func validPrivateKey(privateKey ed25519.PrivateKey) bool {
	if len(privateKey) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	return subtle.ConstantTimeCompare(privateKey, derived) == 1
}

func validateLocalCertificate(certificate tls.Certificate) error {
	if len(certificate.Certificate) != 1 || certificate.PrivateKey == nil {
		return ErrInvalidCertificate
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return ErrInvalidCertificate
		}
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	signer, signerOK := certificate.PrivateKey.(crypto.Signer)
	if !ok || !signerOK {
		return ErrInvalidCertificate
	}
	signerPublicKey, publicOK := signer.Public().(ed25519.PublicKey)
	if !publicOK || len(signerPublicKey) != ed25519.PublicKeySize || !signerPublicKey.Equal(publicKey) {
		return ErrInvalidCertificate
	}
	if privateKey, privateOK := certificate.PrivateKey.(ed25519.PrivateKey); privateOK && !validPrivateKey(privateKey) {
		return ErrInvalidCertificate
	}
	return nil
}

func validatePins(pins []SPKIPin) error {
	if len(pins) == 0 {
		return ErrInvalidPin
	}
	for _, pin := range pins {
		if pin == (SPKIPin{}) {
			return ErrInvalidPin
		}
	}
	return nil
}

func verifyPinnedPeer(state tls.ConnectionState, pins []SPKIPin, usage x509.ExtKeyUsage, now time.Time) error {
	// VerifyConnection runs before ConnectionState.HandshakeComplete is set.
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) != 1 {
		return ErrPeerVerification
	}
	peer := state.PeerCertificates[0]
	publicKey, ok := peer.PublicKey.(ed25519.PublicKey)
	if !ok || now.Before(peer.NotBefore) || now.After(peer.NotAfter) || peer.IsCA ||
		peer.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasUsage(peer, usage) ||
		peer.CheckSignature(peer.SignatureAlgorithm, peer.RawTBSCertificate, peer.Signature) != nil {
		return ErrPeerVerification
	}
	pin, err := PinPublicKey(publicKey)
	if err != nil {
		return ErrPeerVerification
	}
	for _, expected := range pins {
		if subtle.ConstantTimeCompare(pin[:], expected[:]) == 1 {
			return nil
		}
	}
	return ErrPeerVerification
}

func hasUsage(certificate *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == want {
			return true
		}
	}
	return false
}

func exportBinding(state tls.ConnectionState, label string) (Binding, error) {
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return Binding{}, ErrExporter
	}
	material, err := state.ExportKeyingMaterial(label, nil, bindingSize)
	if err != nil || len(material) != bindingSize {
		return Binding{}, ErrExporter
	}
	var binding Binding
	copy(binding[:], material)
	clear(material)
	return binding, nil
}

func transcriptMessage(transcript TranscriptHash) []byte {
	message := make([]byte, 2+len(transcriptDomain)+len(transcript))
	binary.BigEndian.PutUint16(message[:2], uint16(len(transcriptDomain)))
	copy(message[2:], transcriptDomain)
	copy(message[2+len(transcriptDomain):], transcript[:])
	return message
}
