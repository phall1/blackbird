package localsecurity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

func TestCredentialVaultLifecycle(t *testing.T) {
	t.Parallel()

	store := newFakeSecretStore()
	firstSeed := sha256.Sum256([]byte("installation seed v1"))
	secondSeed := sha256.Sum256([]byte("installation seed v2"))
	vault := NewCredentialVault(store, bytes.NewReader(append(firstSeed[:], secondSeed[:]...)))
	reference, err := InstallationCredentialReference("0198-installation")
	if err != nil {
		t.Fatal(err)
	}

	created, err := vault.CreateCredential(reference)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	defer created.Destroy()
	assertCredentialPublicKey(t, created, firstSeed)
	if _, err := vault.CreateCredential(reference); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate CreateCredential error = %v", err)
	}

	loaded, err := vault.LoadCredential(reference)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	assertCredentialPublicKey(t, loaded, firstSeed)
	loaded.Destroy()
	if _, err := loaded.PublicKey(); !errors.Is(err, ErrCredentialDestroyed) {
		t.Fatalf("destroyed PublicKey error = %v", err)
	}
	if _, err := loaded.Sign(nil, []byte("message"), crypto.Hash(0)); !errors.Is(err, ErrCredentialDestroyed) {
		t.Fatalf("destroyed Sign error = %v", err)
	}
	if got := fmt.Sprintf("%v %#v", loaded, loaded); strings.Contains(got, fmt.Sprintf("%x", firstSeed)) {
		t.Fatal("credential formatting exposed seed material")
	}

	rotated, err := vault.RotateCredential(reference)
	if err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	defer rotated.Destroy()
	assertCredentialPublicKey(t, rotated, secondSeed)
	reloaded, err := vault.LoadCredential(reference)
	if err != nil {
		t.Fatalf("LoadCredential after rotation: %v", err)
	}
	defer reloaded.Destroy()
	assertCredentialPublicKey(t, reloaded, secondSeed)

	certificate, pin, err := reloaded.NewCertificate(testValidity())
	if err != nil {
		t.Fatalf("credential NewCertificate: %v", err)
	}
	if _, err := PairingServerTLSConfig(certificate); err != nil {
		t.Fatalf("credential-backed certificate rejected: %v", err)
	}
	publicKey, err := reloaded.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	wantPin, err := PinPublicKey(publicKey)
	if err != nil || pin != wantPin {
		t.Fatalf("credential certificate pin = %x, want %x, error = %v", pin, wantPin, err)
	}

	if err := vault.DeleteCredential(reference); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if _, err := vault.LoadCredential(reference); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("load deleted credential error = %v", err)
	}
	if err := vault.DeleteCredential(reference); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("delete absent credential error = %v", err)
	}
	if _, err := vault.RotateCredential(reference); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("rotate absent credential error = %v", err)
	}
}

func TestCredentialVaultKindsValidationAndFailureSemantics(t *testing.T) {
	t.Parallel()

	for _, invalid := range []string{"", " leading", "has/slash", "has:colon", strings.Repeat("a", 129)} {
		if _, err := DeviceCredentialReference(invalid); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("DeviceCredentialReference(%q) error = %v", invalid, err)
		}
	}
	if _, err := NewCredentialReference("provider", "valid-id"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("unsupported credential kind error = %v", err)
	}

	installation, _ := InstallationCredentialReference("same-id")
	device, _ := DeviceCredentialReference("same-id")
	store := newFakeSecretStore()
	vault := NewCredentialVault(store, bytes.NewReader(make([]byte, 2*ed25519.SeedSize)))
	installationCredential, err := vault.CreateCredential(installation)
	if err != nil {
		t.Fatal(err)
	}
	defer installationCredential.Destroy()
	deviceCredential, err := vault.CreateCredential(device)
	if err != nil {
		t.Fatalf("device and installation references collided: %v", err)
	}
	defer deviceCredential.Destroy()

	unavailable := NewCredentialVault(&fakeSecretStore{getErr: errors.New("vault offline")}, bytes.NewReader(nil))
	if _, err := unavailable.LoadCredential(installation); !errors.Is(err, ErrVaultUnavailable) || strings.Contains(err.Error(), installation.identifier) {
		t.Fatalf("unavailable vault error = %v", err)
	}
	if _, err := NewCredentialVault(nil, nil).LoadCredential(installation); !errors.Is(err, ErrVaultUnavailable) {
		t.Fatalf("nil vault error = %v", err)
	}

	corruptStore := newFakeSecretStore()
	corruptStore.values[credentialService+"\x00"+device.account()] = []byte("not an Ed25519 seed")
	if _, err := NewCredentialVault(corruptStore, nil).LoadCredential(device); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("corrupt seed error = %v", err)
	}
}

func TestCertificateAndCanonicalSPKIPin(t *testing.T) {
	t.Parallel()

	seed := sha256.Sum256([]byte("local peer key material"))
	certificate, pin, err := NewCertificate(seed[:], testValidity())
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	leaf := certificate.Leaf
	if leaf == nil {
		t.Fatal("certificate leaf is nil")
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T", leaf.PublicKey)
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if want := sha256.Sum256(spki); pin != want {
		t.Fatalf("pin = %x, want canonical SPKI digest %x", pin, want)
	}
	if leaf.SignatureAlgorithm != x509.PureEd25519 || leaf.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("certificate algorithms = (%v, %v)", leaf.SignatureAlgorithm, leaf.PublicKeyAlgorithm)
	}

	privateMaterial := ed25519.NewKeyFromSeed(seed[:])
	fromPrivate, privatePin, err := NewCertificate(privateMaterial, testValidity())
	if err != nil {
		t.Fatalf("NewCertificate(private key): %v", err)
	}
	if privatePin != pin || !bytes.Equal(fromPrivate.Leaf.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("seed and private-key forms produced different public identities")
	}

	malformed := append(ed25519.PrivateKey(nil), privateMaterial...)
	malformed[len(malformed)-1] ^= 1
	if _, _, err := NewCertificate(malformed, testValidity()); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("malformed private key error = %v", err)
	}
}

func TestPinnedMutualTLS13AndExporterBindings(t *testing.T) {
	t.Parallel()

	serverCertificate, serverPin := testCertificate(t, "server")
	clientCertificate, clientPin := testCertificate(t, "client")
	serverConfig := mustServerConfig(t, serverCertificate, clientPin)
	clientConfig := mustClientConfig(t, clientCertificate, serverPin)

	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 ||
		clientConfig.MinVersion != tls.VersionTLS13 || clientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatal("TLS configurations are not locked to TLS 1.3")
	}
	if serverConfig.ClientAuth != tls.RequireAnyClientCert || serverConfig.ClientCAs != nil {
		t.Fatal("server does not use explicit mTLS verification without ambient roots")
	}
	if !clientConfig.InsecureSkipVerify || clientConfig.RootCAs != nil || clientConfig.VerifyConnection == nil {
		t.Fatal("client does not replace ambient root trust with explicit pin verification")
	}

	clientState, serverState, clientErr, serverErr := handshake(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	if clientState.Version != tls.VersionTLS13 || serverState.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated versions = (%x, %x)", clientState.Version, serverState.Version)
	}
	pairClient, err := PairingBinding(clientState)
	if err != nil {
		t.Fatalf("client PairingBinding: %v", err)
	}
	pairServer, err := PairingBinding(serverState)
	if err != nil {
		t.Fatalf("server PairingBinding: %v", err)
	}
	sessionClient, err := SessionBinding(clientState)
	if err != nil {
		t.Fatalf("client SessionBinding: %v", err)
	}
	sessionServer, err := SessionBinding(serverState)
	if err != nil {
		t.Fatalf("server SessionBinding: %v", err)
	}
	if pairClient != pairServer || sessionClient != sessionServer {
		t.Fatal("TLS peers derived different exporter bindings")
	}
	if pairClient == sessionClient {
		t.Fatal("reviewed pairing and session labels are not domain separated")
	}
}

func TestFirstContactPinsDaemonWithoutPretrustingClient(t *testing.T) {
	t.Parallel()
	serverCertificate, serverPin := testCertificate(t, "pairing server")
	serverConfig, err := PairingServerTLSConfig(serverCertificate)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := PairingClientTLSConfig(serverPin)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientConfig.Certificates) != 0 || serverConfig.ClientAuth != tls.NoClientCert {
		t.Fatal("first-contact TLS required a pretrusted client certificate")
	}
	clientState, serverState, clientErr, serverErr := handshake(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("first-contact handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	if len(clientState.PeerCertificates) != 1 || len(serverState.PeerCertificates) != 0 {
		t.Fatal("first-contact peer certificate shape is incorrect")
	}
	clientBinding, err := PairingBinding(clientState)
	if err != nil {
		t.Fatal(err)
	}
	serverBinding, err := PairingBinding(serverState)
	if err != nil {
		t.Fatal(err)
	}
	if clientBinding != serverBinding {
		t.Fatal("first-contact peers derived different pairing bindings")
	}
}

func TestPinnedTLSRejectsMITMAndDowngrade(t *testing.T) {
	t.Parallel()

	serverCertificate, serverPin := testCertificate(t, "server target")
	clientCertificate, clientPin := testCertificate(t, "client target")
	attackerCertificate, attackerPin := testCertificate(t, "attacker")

	t.Run("server substitution", func(t *testing.T) {
		clientConfig := mustClientConfig(t, clientCertificate, serverPin)
		serverConfig := mustServerConfig(t, attackerCertificate, clientPin)
		_, _, clientErr, _ := handshake(clientConfig, serverConfig)
		if !errors.Is(clientErr, ErrPeerVerification) {
			t.Fatalf("client MITM error = %v", clientErr)
		}
	})

	t.Run("client substitution", func(t *testing.T) {
		clientConfig := mustClientConfig(t, attackerCertificate, serverPin)
		serverConfig := mustServerConfig(t, serverCertificate, clientPin)
		_, _, _, serverErr := handshake(clientConfig, serverConfig)
		if !errors.Is(serverErr, ErrPeerVerification) {
			t.Fatalf("server MITM error = %v (attacker pin %x)", serverErr, attackerPin)
		}
	})

	t.Run("TLS 1.2 downgrade", func(t *testing.T) {
		clientConfig := mustClientConfig(t, clientCertificate, serverPin)
		serverConfig := mustServerConfig(t, serverCertificate, clientPin)
		serverConfig.MinVersion = tls.VersionTLS12
		serverConfig.MaxVersion = tls.VersionTLS12
		_, _, clientErr, serverErr := handshake(clientConfig, serverConfig)
		if clientErr == nil || serverErr == nil {
			t.Fatalf("downgrade unexpectedly succeeded: client=%v server=%v", clientErr, serverErr)
		}
	})
}

func TestTranscriptSignatureAndPairingProofReplayBinding(t *testing.T) {
	t.Parallel()

	seed := sha256.Sum256([]byte("transcript signer"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	canonical := []byte(`{"client_nonce":"a","protocol":"blackbird.pair/v1","server_nonce":"b"}`)
	transcript, err := HashTranscript(canonical)
	if err != nil {
		t.Fatalf("HashTranscript: %v", err)
	}
	signature, err := SignTranscript(privateKey, transcript)
	if err != nil {
		t.Fatalf("SignTranscript: %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if err := VerifyTranscript(publicKey, transcript, signature); err != nil {
		t.Fatalf("VerifyTranscript: %v", err)
	}
	changed, err := HashTranscript(append(append([]byte(nil), canonical...), ' '))
	if err != nil {
		t.Fatalf("HashTranscript(changed): %v", err)
	}
	if err := VerifyTranscript(publicKey, changed, signature); !errors.Is(err, ErrInvalidTranscript) {
		t.Fatalf("transcript substitution error = %v", err)
	}

	serverCertificate, serverPin := testCertificate(t, "proof server")
	clientCertificate, clientPin := testCertificate(t, "proof client")
	clientConfig := mustClientConfig(t, clientCertificate, serverPin)
	serverConfig := mustServerConfig(t, serverCertificate, clientPin)
	firstClient, _, clientErr, serverErr := handshake(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("first handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	secondClient, _, clientErr, serverErr := handshake(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("second handshake errors: client=%v server=%v", clientErr, serverErr)
	}
	firstBinding, err := PairingBinding(firstClient)
	if err != nil {
		t.Fatalf("first PairingBinding: %v", err)
	}
	secondBinding, err := PairingBinding(secondClient)
	if err != nil {
		t.Fatalf("second PairingBinding: %v", err)
	}
	if firstBinding == secondBinding {
		t.Fatal("separate TLS handshakes produced the same exporter binding")
	}
	secret := sha256.Sum256([]byte("one-time invitation secret"))
	proof, err := PairingProof(secret[:], firstBinding, transcript)
	if err != nil {
		t.Fatalf("PairingProof: %v", err)
	}
	if err := VerifyPairingProof(secret[:], firstBinding, transcript, proof[:]); err != nil {
		t.Fatalf("VerifyPairingProof: %v", err)
	}
	if err := VerifyPairingProof(secret[:], secondBinding, transcript, proof[:]); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("cross-connection replay error = %v", err)
	}
	if err := VerifyPairingProof(secret[:], firstBinding, changed, proof[:]); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("cross-transcript replay error = %v", err)
	}

	for _, err := range []error{
		VerifyPairingProof(secret[:], secondBinding, transcript, proof[:]),
		VerifyTranscript(publicKey, changed, signature),
	} {
		if strings.Contains(err.Error(), string(secret[:])) || strings.Contains(err.Error(), string(proof[:])) {
			t.Fatal("security error exposed raw secret or proof")
		}
	}
}

func TestSecurityPrimitivesRejectMissingInputs(t *testing.T) {
	t.Parallel()

	if _, err := PairedClientTLSConfig(tls.Certificate{}); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("empty client certificate error = %v", err)
	}
	certificate, _ := testCertificate(t, "missing pins")
	if _, err := PairedServerTLSConfig(certificate); !errors.Is(err, ErrInvalidPin) {
		t.Fatalf("empty pin set error = %v", err)
	}
	if _, err := HashTranscript(nil); !errors.Is(err, ErrInvalidTranscript) {
		t.Fatalf("empty transcript error = %v", err)
	}
	if _, err := PairingProof(make([]byte, 31), Binding{1}, TranscriptHash{1}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("short invitation secret error = %v", err)
	}
	if _, err := PairingBinding(tls.ConnectionState{}); !errors.Is(err, ErrExporter) {
		t.Fatalf("pre-handshake exporter error = %v", err)
	}
}

func TestTransportAccessCredentialLifecycleAndLocalDenials(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	entropy := append(bytes.Repeat([]byte{0x51}, sha256.Size), bytes.Repeat([]byte{0x52}, sha256.Size)...)
	entropy = append(entropy, bytes.Repeat([]byte{0x53}, sha256.Size)...)
	issuer, err := NewTransportAccessIssuer(bytes.NewReader(entropy), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewTransportAccessIssuer: %v", err)
	}
	claims := TransportAccessClaims{
		PrincipalID: "principal-1", DeviceID: "device-1", AuthorityEpoch: "epoch-opaque-a",
		GrantsRevision: 4, CredentialVersion: 2, RevocationVersion: 7,
	}
	current := TransportAccessCurrent{
		AuthorityEpoch: claims.AuthorityEpoch, GrantsRevision: claims.GrantsRevision,
		CredentialVersion: claims.CredentialVersion, RevocationVersion: claims.RevocationVersion,
	}
	binding := Binding{1, 2, 3}
	credential, err := issuer.Issue(claims, binding, 10*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	defer credential.Destroy()
	material, err := credential.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	defer clear(material)
	request := LocalAccessRequest{Credential: material, Binding: binding}
	got, err := issuer.VerifyLocalAccess(request, current)
	if err != nil || got != claims {
		t.Fatalf("VerifyLocalAccess = (%+v, %v), want issued claims", got, err)
	}

	denials := []struct {
		name    string
		request LocalAccessRequest
		current TransportAccessCurrent
	}{
		{"unpaired local process", LocalAccessRequest{Binding: binding}, current},
		{"browser origin", LocalAccessRequest{Credential: material, Binding: binding, BrowserOrigin: "https://evil.example"}, current},
		{"connection change", LocalAccessRequest{Credential: material, Binding: Binding{9}}, current},
		{"epoch change", request, TransportAccessCurrent{"epoch-opaque-b", 4, 2, 7}},
		{"grant change", request, TransportAccessCurrent{claims.AuthorityEpoch, 5, 2, 7}},
		{"credential rotation", request, TransportAccessCurrent{claims.AuthorityEpoch, 4, 3, 7}},
		{"revocation change", request, TransportAccessCurrent{claims.AuthorityEpoch, 4, 2, 8}},
	}
	for _, test := range denials {
		t.Run(test.name, func(t *testing.T) {
			if _, verifyErr := issuer.VerifyLocalAccess(test.request, test.current); !errors.Is(verifyErr, ErrAccessDenied) {
				t.Fatalf("VerifyLocalAccess error = %v", verifyErr)
			}
		})
	}

	replacementClaims := claims
	replacementClaims.CredentialVersion++
	forgedClaims := replacementClaims
	forgedClaims.PrincipalID = "principal-2"
	if _, err := issuer.Rotate(material, forgedClaims, binding, 10*time.Minute); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("cross-principal rotation error = %v", err)
	}
	forgedClaims = replacementClaims
	forgedClaims.DeviceID = "device-2"
	if _, err := issuer.Rotate(material, forgedClaims, binding, 10*time.Minute); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("cross-device rotation error = %v", err)
	}
	if _, err := issuer.VerifyLocalAccess(request, current); err != nil {
		t.Fatalf("rejected rotation invalidated old credential: %v", err)
	}
	replacement, err := issuer.Rotate(material, replacementClaims, binding, 10*time.Minute)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	defer replacement.Destroy()
	if _, err := issuer.VerifyLocalAccess(request, current); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("rotated credential remained valid: %v", err)
	}
	replacementMaterial, _ := replacement.Bytes()
	defer clear(replacementMaterial)
	replacementCurrent := current
	replacementCurrent.CredentialVersion++
	if _, err := issuer.VerifyLocalAccess(
		LocalAccessRequest{Credential: replacementMaterial, Binding: binding}, replacementCurrent,
	); err != nil {
		t.Fatalf("replacement credential rejected: %v", err)
	}
	if err := issuer.Revoke(replacementMaterial); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := issuer.VerifyLocalAccess(
		LocalAccessRequest{Credential: replacementMaterial, Binding: binding}, replacementCurrent,
	); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("revoked credential error = %v", err)
	}
}

func TestTransportAccessExpiryAndRestartInvalidation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	entropy := append(bytes.Repeat([]byte{0x63}, sha256.Size), bytes.Repeat([]byte{0x64}, sha256.Size)...)
	entropy = append(entropy, bytes.Repeat([]byte{0x65}, sha256.Size)...)
	entropy = append(entropy, bytes.Repeat([]byte{0x66}, sha256.Size)...)
	issuer, err := NewTransportAccessIssuer(
		bytes.NewReader(entropy), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	claims := TransportAccessClaims{"principal", "device", "epoch", 1, 1, 1}
	current := TransportAccessCurrent{"epoch", 1, 1, 1}
	binding := Binding{1}
	credential, err := issuer.Issue(claims, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	material, _ := credential.Bytes()
	defer clear(material)
	request := LocalAccessRequest{Credential: material, Binding: binding}
	now = now.Add(time.Minute)
	if _, err := issuer.VerifyLocalAccess(request, current); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("expired credential error = %v", err)
	}

	now = now.Add(-time.Minute)
	fresh, err := issuer.Issue(claims, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Destroy()
	freshMaterial, _ := fresh.Bytes()
	defer clear(freshMaterial)
	if err := issuer.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if _, err := issuer.VerifyLocalAccess(
		LocalAccessRequest{Credential: freshMaterial, Binding: binding}, current,
	); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("pre-restart credential error = %v", err)
	}
}

func TestPairingInvitationRestartResumeAttemptAndExpiryControls(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	registry := NewPairingInvitationRegistry(
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 16+sha256.Size)), func() time.Time { return now },
	)
	identifier, secret, err := registry.Issue(5 * time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	registry.Restart()
	if err := registry.Redeem(identifier, secret); !errors.Is(err, ErrInvitationSuspended) {
		t.Fatalf("post-restart redemption error = %v", err)
	}
	if err := registry.Resume(identifier, secret); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := registry.Redeem(identifier, secret); err != nil {
		t.Fatalf("Redeem after resume: %v", err)
	}
	if err := registry.Redeem(identifier, secret); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("reused invitation error = %v", err)
	}

	expiryRegistry := NewPairingInvitationRegistry(
		bytes.NewReader(bytes.Repeat([]byte{0x43}, 16+sha256.Size)), func() time.Time { return now },
	)
	expiringID, expiringSecret, _ := expiryRegistry.Issue(time.Minute)
	now = now.Add(time.Minute)
	if err := expiryRegistry.Redeem(expiringID, expiringSecret); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("expired invitation error = %v", err)
	}

	attemptRegistry := NewPairingInvitationRegistry(
		bytes.NewReader(bytes.Repeat([]byte{0x44}, 16+sha256.Size)), func() time.Time { return now },
	)
	attemptID, attemptSecret, _ := attemptRegistry.Issue(time.Minute)
	wrongSecret := PairingInvitationSecret{material: [sha256.Size]byte{1}}
	for range maxPairingAttempts {
		if err := attemptRegistry.Redeem(attemptID, wrongSecret); !errors.Is(err, ErrInvitationInvalid) {
			t.Fatalf("failed attempt error = %v", err)
		}
	}
	if err := attemptRegistry.Redeem(attemptID, attemptSecret); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("attempt-exhausted invitation error = %v", err)
	}
}

func TestVaultSignerCompositionAndNoSecretLeakEvidence(t *testing.T) {
	t.Parallel()

	seed := sha256.Sum256([]byte("seeded vault signer secret"))
	store := newFakeSecretStore()
	reference, _ := DeviceCredentialReference("leak-test-device")
	vault := NewCredentialVault(store, bytes.NewReader(seed[:]))
	credential, err := vault.CreateCredential(reference)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	transcript, _ := HashTranscript([]byte(`{"protocol":"blackbird.pair/v1"}`))
	signature, err := credential.SignTranscript(transcript)
	if err != nil {
		t.Fatalf("vault SignTranscript: %v", err)
	}
	publicKey, _ := credential.PublicKey()
	if err := VerifyTranscript(publicKey, transcript, signature); err != nil {
		t.Fatalf("VerifyTranscript: %v", err)
	}
	certificate, _, err := credential.NewCertificate(testValidity())
	if err != nil || certificate.PrivateKey != credential {
		t.Fatalf("vault signer was not retained by certificate: key=%T error=%v", certificate.PrivateKey, err)
	}
	invitationBytes := bytes.Repeat([]byte{0x71}, sha256.Size)
	invitationRegistry := NewPairingInvitationRegistry(
		bytes.NewReader(append(bytes.Repeat([]byte{0x70}, 16), invitationBytes...)), time.Now,
	)
	invitationID, invitation, err := invitationRegistry.Issue(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	accessBytes := bytes.Repeat([]byte{0x73}, sha256.Size)
	accessEntropy := append(bytes.Repeat([]byte{0x72}, sha256.Size), accessBytes...)
	accessIssuer, err := NewTransportAccessIssuer(bytes.NewReader(accessEntropy), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := accessIssuer.Issue(
		TransportAccessClaims{"principal", "device", "epoch", 1, 1, 1}, Binding{1}, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer access.Destroy()

	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	logger.Printf(
		"credential=%v invitation=%v access=%v reference=%v error=%v",
		credential, invitation, access, reference, ErrAccessDenied,
	)
	databaseEvidence, err := json.Marshal(struct {
		CredentialReference string                     `json:"credential_reference"`
		PublicKey           []byte                     `json:"public_key"`
		InvitationID        string                     `json:"invitation_id"`
		Invitation          PairingInvitationSecret    `json:"invitation"`
		Access              *TransportAccessCredential `json:"access"`
	}{reference.String(), publicKey, invitationID.String(), invitation, access})
	if err != nil {
		t.Fatal(err)
	}
	environmentEvidence := []string{"BLACKBIRD_CREDENTIAL_REFERENCE=" + reference.String()}
	argumentEvidence := []string{"blackbird", "--credential-reference", reference.String()}
	errorEvidence := fmt.Errorf("transport authentication: %w", ErrAccessDenied).Error()
	formatEvidence := fmt.Sprintf(
		"%v %#v %+v %x %q %v %#v %+v %x %q %v %#v %+v %x %q",
		credential, credential, credential, credential, credential,
		invitation, invitation, invitation, invitation, invitation,
		access, access, access, access, access,
	)
	allEvidence := strings.Join(environmentEvidence, "\n") + strings.Join(argumentEvidence, "\n") +
		strings.Join(os.Environ(), "\n") + strings.Join(os.Args, "\n") + logs.String() +
		string(databaseEvidence) + errorEvidence + formatEvidence
	for _, forbidden := range []string{
		string(seed[:]), hex.EncodeToString(seed[:]), base64.StdEncoding.EncodeToString(seed[:]),
		string(invitationBytes), hex.EncodeToString(invitationBytes), base64.StdEncoding.EncodeToString(invitationBytes),
		string(accessBytes), hex.EncodeToString(accessBytes), base64.StdEncoding.EncodeToString(accessBytes),
	} {
		if strings.Contains(allEvidence, forbidden) {
			t.Fatalf("environment/argv/log/error/format/database evidence leaked seeded key material")
		}
	}
	if !strings.Contains(formatEvidence, "REDACTED") {
		t.Fatal("credential formatting did not visibly redact the secret")
	}
}

func TestVaultRecoveryCapsuleSignerLookupRejectsForgeryAndRedacts(t *testing.T) {
	t.Parallel()

	seed := sha256.Sum256([]byte("recovery capsule vault seed"))
	store := newFakeSecretStore()
	vault := NewCredentialVault(store, bytes.NewReader(seed[:]))
	reference, err := InstallationCredentialReference("recovery-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := vault.CreateCredential(reference)
	if err != nil {
		t.Fatal(err)
	}
	credential.Destroy()

	assurance, _ := domain.NewAssuranceClass("hardware_key")
	adapters, err := NewProductionOrchestrationAdapters(
		vault, map[string]CredentialReference{"recovery-v1": reference},
		NewAuthenticationRegistry(), NewPolicyRegistry(), assurance, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		t.Fatal(err)
	}
	lookup := adapters.SignerLookup
	if adapters.EffectPlanner == nil || adapters.DenialPolicy == nil || adapters.Authentication == nil ||
		adapters.Policy == nil || adapters.LockedAuthorization == nil || adapters.ReplayDisclosure == nil ||
		adapters.Presentations == nil {
		t.Fatal("production adapter constructor omitted a supported dependency")
	}
	signer, err := lookup.PrepareRecoveryCapsuleSigner(t.Context(), "recovery-v1")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("blackbird-recovery-capsule-signature/v1\x00bounded digest")
	signature, err := signer.SignRecoveryCapsule(t.Context(), message)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signer.Ed25519PublicKey()
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("vault-backed recovery signature did not verify")
	}
	forged := append([]byte(nil), signature...)
	forged[0] ^= 1
	if ed25519.Verify(publicKey, message, forged) || ed25519.Verify(publicKey, append(message, 0), signature) {
		t.Fatal("forged or cross-message recovery signature verified")
	}

	formatted := fmt.Sprintf("%v %#v %+v", signer, signer, signer)
	for _, forbidden := range []string{
		string(seed[:]), hex.EncodeToString(seed[:]), base64.StdEncoding.EncodeToString(seed[:]),
	} {
		if strings.Contains(formatted, forbidden) {
			t.Fatal("recovery signer formatting exposed seed material")
		}
	}
	if !strings.Contains(formatted, "REDACTED") {
		t.Fatal("recovery signer formatting was not visibly redacted")
	}
	if _, err := lookup.PrepareRecoveryCapsuleSigner(t.Context(), "unknown-key"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("unknown signer error = %v", err)
	}
}

func TestAuthenticationAndPolicyPreparersRejectForgedAndStaleEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	principal, _ := domain.ParsePrincipalID(proofUUID(120))
	device, _ := domain.ParseDeviceID(proofUUID(121))
	installation, _ := domain.ParseInstallationID(proofUUID(122))
	scope, _ := domain.InstallationScope(installation)
	authority, _ := domain.ParseAuthorityID(proofUUID(123))
	provenance, _ := application.NewAuditProvenanceEvidence(authority, nil)
	audience, _ := domain.NewCredentialAudience("blackbird:local")
	fingerprint, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("authenticated credential")))
	params := application.AuthenticationRequestParams{
		Operation: application.CommandRegisterPrincipal, Scope: scope, PrincipalID: principal,
		PrincipalRevision: domain.InitialVersion(), DeviceID: &device,
		DeviceRevision: domain.InitialVersion(), DeviceTrustRevision: domain.InitialVersion(),
		DeviceRevokeRevision: domain.InitialVersion(), CredentialFingerprint: fingerprint,
		ChannelBinding: application.DigestBytes([]byte("authenticated channel")), Audience: audience,
		AuditProvenance: provenance, VerifiedAt: now,
	}
	request, err := application.NewAuthenticationRequest(params)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewAuthenticationRegistry()
	if err := registry.Register(request); err != nil {
		t.Fatal(err)
	}
	preparer, _ := NewAuthenticationPreparer(registry)
	decision, err := preparer.PrepareAuthentication(t.Context(), request)
	if err != nil || decision.Kind() != application.AuthenticationValid {
		t.Fatalf("registered authentication = (%s, %v)", decision.Kind(), err)
	}

	attacks := map[string]func(*application.AuthenticationRequestParams){
		"forged principal": func(value *application.AuthenticationRequestParams) {
			value.PrincipalID, _ = domain.ParsePrincipalID(proofUUID(124))
		},
		"stale principal": func(value *application.AuthenticationRequestParams) {
			value.PrincipalRevision, _ = domain.NewVersion(2)
		},
		"stale credential": func(value *application.AuthenticationRequestParams) {
			value.DeviceTrustRevision, _ = domain.NewVersion(2)
		},
		"revoked device revision": func(value *application.AuthenticationRequestParams) {
			value.DeviceRevokeRevision, _ = domain.NewVersion(2)
		},
		"cross audience": func(value *application.AuthenticationRequestParams) {
			value.Audience, _ = domain.NewCredentialAudience("blackbird:other")
		},
		"cross channel": func(value *application.AuthenticationRequestParams) {
			value.ChannelBinding = application.DigestBytes([]byte("other channel"))
		},
	}
	for name, mutate := range attacks {
		t.Run(name, func(t *testing.T) {
			forgedParams := params
			mutate(&forgedParams)
			forged, newErr := application.NewAuthenticationRequest(forgedParams)
			if newErr != nil {
				t.Fatal(newErr)
			}
			if _, prepareErr := preparer.PrepareAuthentication(t.Context(), forged); !errors.Is(prepareErr, ErrAccessDenied) {
				t.Fatalf("forged authentication error = %v", prepareErr)
			}
		})
	}

	policyRevision, _ := domain.NewPolicyRevision("local-policy:v1")
	policyDigest := application.DigestBytes([]byte("local policy"))
	policies := NewPolicyRegistry()
	if err := policies.Register(scope, policyRevision, policyDigest); err != nil {
		t.Fatal(err)
	}
	policyPreparer, _ := NewPolicyPreparer(policies)
	policyRequest, _ := application.NewPolicyPreparationRequest(request, policyRevision, policyDigest)
	if _, err := policyPreparer.PreparePolicy(t.Context(), policyRequest); err != nil {
		t.Fatal(err)
	}
	staleRevision, _ := domain.NewPolicyRevision("local-policy:v0")
	stalePolicy, _ := application.NewPolicyPreparationRequest(request, staleRevision, policyDigest)
	if _, err := policyPreparer.PreparePolicy(t.Context(), stalePolicy); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("stale policy revision error = %v", err)
	}
	staleDigest, _ := application.NewPolicyPreparationRequest(request, policyRevision, application.DigestBytes([]byte("forged policy")))
	if _, err := policyPreparer.PreparePolicy(t.Context(), staleDigest); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("stale policy digest error = %v", err)
	}
	if err := registry.Revoke(request); err != nil {
		t.Fatal(err)
	}
	if _, err := preparer.PrepareAuthentication(t.Context(), request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("replay after revocation error = %v", err)
	}
}

func TestGeneratedPresentationCredentialIsBoundAndDeliveredOnce(t *testing.T) {
	t.Parallel()
	principal, _ := domain.ParsePrincipalID(proofUUID(130))
	device, _ := domain.ParseDeviceID(proofUUID(131))
	session, _ := domain.ParseActorSessionID(proofUUID(132))
	audience, _ := domain.NewCredentialAudience("blackbird:session")
	delivery := &recordingPresentationDelivery{}
	request, err := application.NewPresentationCredentialRequest(
		application.CommandStartActorSession, principal, &device, session, audience,
		application.DigestBytes([]byte("session channel")), "delivery-132", delivery,
	)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x91}, sha256.Size)
	preparer, _ := NewGeneratedPresentationCredentialPreparer(bytes.NewReader(secret))
	binding, err := preparer.PreparePresentationCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if binding.IsZero() || binding.Audience() != audience || delivery.calls != 1 ||
		delivery.reference != "delivery-132" || !bytes.Equal(delivery.credential, secret) {
		t.Fatal("generated credential was not bound and delivered exactly once")
	}
	if bytes.Contains([]byte(fmt.Sprintf("%v %#v", binding, binding)), secret) {
		t.Fatal("presentation binding exposed plaintext credential")
	}
	if _, err := preparer.PreparePresentationCredential(t.Context(), request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("reused delivery error = %v", err)
	}
}

func TestGeneratedPresentationCredentialConsumesFailedDeliveryReference(t *testing.T) {
	t.Parallel()
	principal, _ := domain.ParsePrincipalID(proofUUID(133))
	session, _ := domain.ParseActorSessionID(proofUUID(134))
	audience, _ := domain.NewCredentialAudience("blackbird:session")
	delivery := &recordingPresentationDelivery{err: errors.New("delivery unavailable")}
	request, err := application.NewPresentationCredentialRequest(
		application.CommandStartActorSession, principal, nil, session, audience,
		application.DigestBytes([]byte("retry channel")), "delivery-134", delivery,
	)
	if err != nil {
		t.Fatal(err)
	}
	preparer, _ := NewGeneratedPresentationCredentialPreparer(bytes.NewReader(bytes.Repeat([]byte{0x92}, 2*sha256.Size)))
	if _, err := preparer.PreparePresentationCredential(t.Context(), request); !errors.Is(err, ErrSecurityDependency) {
		t.Fatalf("failed delivery error = %v", err)
	}
	delivery.err = nil
	if _, err := preparer.PreparePresentationCredential(t.Context(), request); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("failed delivery reference was reusable: %v", err)
	}
}

type recordingPresentationDelivery struct {
	calls      int
	reference  string
	credential []byte
	err        error
}

func (delivery *recordingPresentationDelivery) DeliverPresentationCredential(
	_ context.Context,
	reference string,
	credential []byte,
) error {
	delivery.calls++
	delivery.reference = reference
	delivery.credential = append([]byte(nil), credential...)
	return delivery.err
}

func TestBootstrapProofVerifierBindsInvitationPrincipalDeviceAndChannel(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	invitationEntropy := append(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x32}, sha256.Size)...)
	invitations := NewPairingInvitationRegistry(bytes.NewReader(invitationEntropy), func() time.Time { return now })
	pairingID, secret, err := invitations.Issue(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	deviceSeed := sha256.Sum256([]byte("bootstrap-device-key"))
	deviceKey := ed25519.NewKeyFromSeed(deviceSeed[:])
	keyReference, _ := domain.NewPublicKeyReference("keyref:bootstrap-device")
	vaultReference, _ := DeviceCredentialReference("bootstrap-device")
	vault := NewCredentialVault(newFakeSecretStore(), bytes.NewReader(deviceSeed[:]))
	vaultCredential, err := vault.CreateCredential(vaultReference)
	if err != nil {
		t.Fatal(err)
	}
	vaultCredential.Destroy()
	keys, err := NewProofPublicKeyRegistry(vault, map[string]CredentialReference{
		keyReference.String(): vaultReference,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	challenges := NewProofChallengeRegistry(func() time.Time { return now })
	context := testBootstrapProofContext(t, pairingID, keyReference, Binding{1, 2, 3})
	if err := challenges.RegisterBootstrap(context); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCryptographicProofVerifier(invitations, keys, challenges)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewBootstrapProofEvidence(context, secret, []byte("client nonce"), []byte("server nonce"), deviceKey)
	if err != nil {
		t.Fatal(err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(evidence.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown field":   func(value map[string]any) { value["unexpected"] = true },
		"unknown version": func(value map[string]any) { value["version"] = float64(2) },
		"wrong purpose":   func(value map[string]any) { value["purpose"] = "device_pairing" },
		"cross channel": func(value map[string]any) {
			value["channel_binding"] = encodeProofBytes(bytes.Repeat([]byte{9}, bindingSize))
		},
		"forged signature": func(value map[string]any) {
			value["signature"] = encodeProofBytes(bytes.Repeat([]byte{9}, ed25519.SignatureSize))
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyEnvelope := cloneJSONMap(t, envelope)
			mutate(copyEnvelope)
			encoded, _ := json.Marshal(copyEnvelope)
			forged, newErr := application.NewBootstrapProofEvidence(encoded)
			if newErr != nil {
				t.Fatal(newErr)
			}
			_, verifyErr := verifier.VerifyBootstrapProof(t.Context(), forged)
			if !errors.Is(verifyErr, ErrInvalidProof) {
				t.Fatalf("noncanonical or invalid envelope error = %v", verifyErr)
			}
		})
	}
	var canonicalForgery bootstrapProofEnvelopeV1
	if err := json.Unmarshal(evidence.Bytes(), &canonicalForgery); err != nil {
		t.Fatal(err)
	}
	canonicalForgery.Signature = encodeProofBytes(bytes.Repeat([]byte{9}, ed25519.SignatureSize))
	forgedBytes, _ := json.Marshal(canonicalForgery)
	forgedEvidence, _ := application.NewBootstrapProofEvidence(forgedBytes)
	forgedVerification, err := verifier.VerifyBootstrapProof(t.Context(), forgedEvidence)
	if err != nil || forgedVerification.Decision() != application.ProofCryptographicallyRejected {
		t.Fatalf("canonical signature forgery = (%v, %v)", forgedVerification.Decision(), err)
	}

	verification, err := verifier.VerifyBootstrapProof(t.Context(), evidence)
	if err != nil || verification.Decision() != application.ProofValid {
		t.Fatalf("valid bootstrap verification = (%v, %v)", verification.Decision(), err)
	}
	replayed, err := verifier.VerifyBootstrapProof(t.Context(), evidence)
	if err != nil || replayed.Decision() != application.ProofCryptographicallyRejected {
		t.Fatalf("replayed bootstrap verification = (%v, %v)", replayed.Decision(), err)
	}
	if err := invitations.Redeem(pairingID, secret); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("verified bootstrap did not consume invitation: %v", err)
	}
}

func TestCeremonyProofVerifierRejectsPurposeScopePrincipalChannelExpiryAndReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	seed := sha256.Sum256([]byte("ceremony signing key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	keyReference, _ := domain.NewPublicKeyReference("keyref:ceremony-device")
	keys, _ := NewProofPublicKeyRegistry(nil, nil, map[string]ed25519.PublicKey{
		keyReference.String(): privateKey.Public().(ed25519.PublicKey),
	})
	invitationRegistry := NewPairingInvitationRegistry(rand.Reader, func() time.Time { return now })
	challenges := NewProofChallengeRegistry(func() time.Time { return now })
	verifier, _ := NewCryptographicProofVerifier(invitationRegistry, keys, challenges)

	contexts := []CeremonyProofContext{
		testMembershipContext(t, keyReference, now),
		testDelegationContext(t, keyReference, now, domain.CeremonyPurposeDelegationActivation),
		testDelegationContext(t, keyReference, now, domain.CeremonyPurposeActorSessionStart),
	}
	verify := []func(context.Context, application.CeremonyProofEvidence) (application.CeremonyProofVerification, error){
		verifier.VerifyMembershipAcceptance,
		verifier.VerifyDelegationActivation,
		verifier.VerifyActorSessionHandoff,
	}
	for index, proofContext := range contexts {
		if err := challenges.RegisterCeremony(proofContext); err != nil {
			t.Fatal(err)
		}
		evidence, err := NewCeremonyProofEvidence(proofContext, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		verification, err := verify[index](t.Context(), evidence)
		if err != nil {
			t.Fatal(err)
		}
		proof, valid := verification.Verified()
		if !valid || proof.Purpose() != proofContext.Purpose || proof.ChallengeID() != proofContext.ChallengeID || proof.ProofDigest().IsZero() {
			t.Fatal("valid ceremony did not return its genuine domain proof")
		}
		replayed, replayErr := verify[index](t.Context(), evidence)
		if replayErr != nil {
			t.Fatal(replayErr)
		}
		if _, valid := replayed.Verified(); valid {
			t.Fatal("ceremony proof replay was accepted")
		}
	}

	base := testMembershipContext(t, keyReference, now)
	base.ChallengeID = mustCeremonyID(t, 90)
	if err := challenges.RegisterCeremony(base); err != nil {
		t.Fatal(err)
	}
	evidence, _ := NewCeremonyProofEvidence(base, privateKey)
	var envelope map[string]any
	_ = json.Unmarshal(evidence.Bytes(), &envelope)
	attacks := map[string]func(map[string]any){
		"cross principal": func(value map[string]any) { value["principal_id"] = proofUUID(91) },
		"cross scope": func(value map[string]any) {
			scope := value["scope"].(map[string]any)
			scope["workspace_id"] = proofUUID(92)
		},
		"cross channel": func(value map[string]any) {
			value["channel_binding"] = encodeProofBytes(bytes.Repeat([]byte{7}, bindingSize))
		},
		"cross purpose": func(value map[string]any) { value["purpose"] = string(domain.CeremonyPurposeDelegationActivation) },
		"unknown field": func(value map[string]any) { value["extra"] = "rejected" },
	}
	for name, mutate := range attacks {
		t.Run(name, func(t *testing.T) {
			copyEnvelope := cloneJSONMap(t, envelope)
			mutate(copyEnvelope)
			encoded, _ := json.Marshal(copyEnvelope)
			forged, _ := application.NewCeremonyProofEvidence(encoded)
			verification, verifyErr := verifier.VerifyMembershipAcceptance(t.Context(), forged)
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			if _, valid := verification.Verified(); valid {
				t.Fatal("substituted ceremony proof was accepted")
			}
		})
	}

	expired := testMembershipContext(t, keyReference, now)
	expired.ChallengeID = mustCeremonyID(t, 93)
	expired.ExpiresAt = now.Add(time.Second)
	if err := challenges.RegisterCeremony(expired); err != nil {
		t.Fatal(err)
	}
	expiredEvidence, _ := NewCeremonyProofEvidence(expired, privateKey)
	now = now.Add(time.Second)
	verification, err := verifier.VerifyMembershipAcceptance(t.Context(), expiredEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid := verification.Verified(); valid {
		t.Fatal("expired ceremony proof was accepted")
	}
}

func TestPairingRedemptionVerifierConstructsBoundAuthorization(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	seed := sha256.Sum256([]byte("pairing redemption key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	keyReference, _ := domain.NewPublicKeyReference("keyref:pairing-redemption")
	keys, _ := NewProofPublicKeyRegistry(nil, nil, map[string]ed25519.PublicKey{
		keyReference.String(): privateKey.Public().(ed25519.PublicKey),
	})
	challenges := NewProofChallengeRegistry(func() time.Time { return now })
	verifier, _ := NewCryptographicProofVerifier(
		NewPairingInvitationRegistry(rand.Reader, func() time.Time { return now }), keys, challenges,
	)
	principal, _ := domain.ParsePrincipalID(proofUUID(101))
	device, _ := domain.ParseDeviceID(proofUUID(102))
	installation, _ := domain.ParseInstallationID(proofUUID(103))
	authority, _ := domain.ParseAuthorityID(proofUUID(104))
	epoch, _ := domain.ParseAuthorityEpoch(proofUUID(105))
	policy, _ := domain.NewPolicyRevision("pairing-policy:v1")
	assurance, _ := domain.NewAssuranceClass("hardware_key")
	spki, _ := PinPublicKey(privateKey.Public().(ed25519.PublicKey))
	spkiDigest, _ := domain.NewCredentialDigest([sha256.Size]byte(spki))
	proofContext := CeremonyProofContext{
		ChallengeID: mustCeremonyID(t, 100), Purpose: domain.CeremonyPurposeDevicePairing,
		PrincipalID: principal, DeviceID: device, InstallationID: installation,
		SignerKey: keyReference, Binding: Binding{4, 5, 6}, ExpiresAt: now.Add(time.Minute),
		PairingAuthorization: &PairingAuthorizationContext{
			AuthorityID: authority, AuthorityEpoch: epoch, PolicyRevision: policy,
			AssuranceClass: assurance, DeviceSPKIFingerprint: spkiDigest,
		},
	}
	if err := challenges.RegisterCeremony(proofContext); err != nil {
		t.Fatal(err)
	}
	evidence, _ := NewCeremonyProofEvidence(proofContext, privateKey)
	var crossDeviceEnvelope ceremonyProofEnvelopeV1
	if err := json.Unmarshal(evidence.Bytes(), &crossDeviceEnvelope); err != nil {
		t.Fatal(err)
	}
	crossDeviceEnvelope.DeviceID = proofUUID(106)
	crossDeviceBytes, _ := json.Marshal(crossDeviceEnvelope)
	crossDeviceEvidence, _ := application.NewCeremonyProofEvidence(crossDeviceBytes)
	crossDeviceDecision, err := verifier.VerifyPairingRedemption(t.Context(), crossDeviceEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid := crossDeviceDecision.Verified(); valid {
		t.Fatal("cross-device pairing proof was accepted")
	}
	decision, err := verifier.VerifyPairingRedemption(t.Context(), evidence)
	if err != nil {
		t.Fatal(err)
	}
	verification, valid := decision.Verified()
	if !valid {
		t.Fatal("valid pairing redemption was rejected")
	}
	authorization := verification.Authorization()
	proof := verification.Proof()
	if authorization.PrincipalID() != principal || authorization.DeviceID() != device ||
		authorization.InstallationID() != installation || authorization.ChallengeID() != proof.ChallengeID() ||
		authorization.TranscriptFingerprint() != proof.ProofDigest() ||
		authorization.Credential().PublicKeyReference() != keyReference ||
		authorization.Credential().SPKIFingerprint() != spkiDigest {
		t.Fatal("pairing authorization was not bound to verified proof context")
	}
	replayed, err := verifier.VerifyPairingRedemption(t.Context(), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid := replayed.Verified(); valid {
		t.Fatal("pairing redemption replay was accepted")
	}
}

func testBootstrapProofContext(
	t *testing.T,
	pairingID PairingInvitationID,
	keyReference domain.PublicKeyReference,
	binding Binding,
) BootstrapProofContext {
	t.Helper()
	invitation, _ := domain.ParseInvitationID(proofUUID(1))
	installation, _ := domain.ParseInstallationID(proofUUID(2))
	installationKey, _ := domain.NewPublicKeyReference("keyref:installation")
	principal, _ := domain.ParsePrincipalID(proofUUID(3))
	principalName, _ := domain.NewDisplayName("Principal")
	device, _ := domain.ParseDeviceID(proofUUID(4))
	deviceName, _ := domain.NewDisplayName("Device")
	spkiDigest, _ := domain.NewCredentialDigest(sha256.Sum256([]byte("device spki")))
	grant, _ := domain.ParseGrantID(proofUUID(5))
	capabilities, _ := domain.NewCapabilitySet(domain.InstallationOwnerCapability())
	return BootstrapProofContext{
		PairingInvitationID: pairingID, InvitationID: invitation, InstallationID: installation,
		InstallationKey: installationKey, Protocol: domain.PairingProtocolV1,
		Role: domain.BootstrapRoleInstallationOwner, PrincipalID: principal,
		PrincipalDisplayName: principalName, DeviceID: device, DeviceDisplayName: deviceName,
		DevicePublicKey: keyReference, DeviceSPKIFingerprint: spkiDigest,
		OwnerGrantID: grant, OwnerCapabilities: capabilities, Binding: binding,
	}
}

func testMembershipContext(t *testing.T, key domain.PublicKeyReference, now time.Time) CeremonyProofContext {
	t.Helper()
	principal, _ := domain.ParsePrincipalID(proofUUID(20))
	workspace, _ := domain.ParseWorkspaceID(proofUUID(21))
	membership, _ := domain.ParseMembershipID(proofUUID(22))
	return CeremonyProofContext{
		ChallengeID: mustCeremonyID(t, 23), Purpose: domain.CeremonyPurposeMembershipAcceptance,
		PrincipalID: principal, WorkspaceID: workspace, MembershipID: membership,
		SignerKey: key, Binding: Binding{1, 3, 5}, ExpiresAt: now.Add(time.Minute),
	}
}

func testDelegationContext(
	t *testing.T,
	key domain.PublicKeyReference,
	now time.Time,
	purpose domain.CeremonyPurpose,
) CeremonyProofContext {
	t.Helper()
	offset := 30
	if purpose == domain.CeremonyPurposeActorSessionStart {
		offset = 40
	}
	principal, _ := domain.ParsePrincipalID(proofUUID(offset))
	workspace, _ := domain.ParseWorkspaceID(proofUUID(offset + 1))
	actor, _ := domain.ParseActorID(proofUUID(offset + 2))
	delegation, _ := domain.ParseActorDelegationID(proofUUID(offset + 3))
	return CeremonyProofContext{
		ChallengeID: mustCeremonyID(t, offset+4), Purpose: purpose, PrincipalID: principal,
		WorkspaceID: workspace, ActorID: actor, DelegationID: delegation,
		SignerKey: key, Binding: Binding{2, 4, 6}, ExpiresAt: now.Add(time.Minute),
	}
}

func mustCeremonyID(t *testing.T, index int) domain.CeremonyID {
	t.Helper()
	id, err := domain.ParseCeremonyID(proofUUID(index))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func proofUUID(index int) string {
	return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", index)
}

func cloneJSONMap(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func testCertificate(t *testing.T, name string) (tls.Certificate, SPKIPin) {
	t.Helper()
	seed := sha256.Sum256([]byte(name))
	certificate, pin, err := NewCertificate(seed[:], testValidity())
	if err != nil {
		t.Fatalf("NewCertificate(%q): %v", name, err)
	}
	return certificate, pin
}

func testValidity() CertificateValidity {
	return CertificateValidity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
}

func mustClientConfig(t *testing.T, certificate tls.Certificate, pin SPKIPin) *tls.Config {
	t.Helper()
	config, err := PairedClientTLSConfig(certificate, pin)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	return config
}

func mustServerConfig(t *testing.T, certificate tls.Certificate, pin SPKIPin) *tls.Config {
	t.Helper()
	config, err := PairedServerTLSConfig(certificate, pin)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	return config
}

func handshake(clientConfig, serverConfig *tls.Config) (tls.ConnectionState, tls.ConnectionState, error, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, err, err
	}
	defer func() { _ = listener.Close() }()

	type result struct {
		state tls.ConnectionState
		err   error
	}
	serverResult := make(chan result, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- result{err: acceptErr}
			return
		}
		server := tls.Server(connection, serverConfig)
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		handshakeErr := server.Handshake()
		serverResult <- result{state: server.ConnectionState(), err: handshakeErr}
		_ = server.Close()
	}()

	connection, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, err, (<-serverResult).err
	}
	client := tls.Client(connection, clientConfig)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	clientErr := client.Handshake()
	clientState := client.ConnectionState()
	_ = client.Close()
	serverOutcome := <-serverResult
	return clientState, serverOutcome.state, clientErr, serverOutcome.err
}

func assertCredentialPublicKey(t *testing.T, credential *Ed25519Credential, seed [ed25519.SeedSize]byte) {
	t.Helper()
	got, err := credential.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	defer clear(privateKey)
	want := privateKey.Public().(ed25519.PublicKey)
	if !got.Equal(want) {
		t.Fatal("credential public key does not match generated seed")
	}
}

type fakeSecretStore struct {
	mu        sync.Mutex
	values    map[string][]byte
	getErr    error
	setErr    error
	deleteErr error
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{values: make(map[string][]byte)}
}

func (store *fakeSecretStore) Set(service, account string, secret []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.setErr != nil {
		return store.setErr
	}
	if store.values == nil {
		store.values = make(map[string][]byte)
	}
	store.values[service+"\x00"+account] = append([]byte(nil), secret...)
	return nil
}

func (store *fakeSecretStore) Get(service, account string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.getErr != nil {
		return nil, store.getErr
	}
	secret, ok := store.values[service+"\x00"+account]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return append([]byte(nil), secret...), nil
}

func (store *fakeSecretStore) Delete(service, account string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deleteErr != nil {
		return store.deleteErr
	}
	delete(store.values, service+"\x00"+account)
	return nil
}

// authorizationInputs is the accepted identity graph behind one authorization
// decision, held as the rehydration parameters each state is built from. Tests
// copy an accepted fixture, spoil exactly one input, and assert the decision
// that follows, so a refactor that moves a predicate shows up as a named
// failure rather than as a silent change of meaning.
type authorizationInputs struct {
	now time.Time

	installation  domain.InstallationID
	authority     domain.AuthorityID
	epoch         domain.AuthorityEpoch
	clientID      domain.ClientInstanceID
	workReference domain.WorkReferenceID
	createdID     domain.PrincipalID

	assurance      domain.AssuranceClass
	guardPolicy    domain.PolicyRevision
	preparedPolicy domain.PolicyRevision
	policyDigest   application.Digest

	principal  domain.PrincipalRehydrationParams
	device     domain.DeviceRehydrationParams
	grant      domain.GrantRehydrationParams
	workspace  domain.WorkspaceRehydrationParams
	membership domain.MembershipRehydrationParams
	actor      domain.ActorRehydrationParams
	delegation domain.ActorDelegationRehydrationParams
	session    domain.ActorSessionRehydrationParams
	binding    sessionBindingInputs
	request    application.AuthenticationRequestParams

	workspaceScoped bool
	withDevice      bool
	withGrant       bool
	withMembership  bool
	withSession     bool

	// withoutAuthorityTime resolves the command as an integrity conflict, the
	// only admitted-free resolution that carries no persisted authority time.
	withoutAuthorityTime bool

	// withoutPrincipal and withoutWorkspaceState drop a state the request still
	// names, which is how a locked read that came back empty reaches authorize.
	withoutPrincipal      bool
	withoutWorkspaceState bool
}

// sessionBindingInputs are the session binding's ingredients rather than the
// sealed value, because a binding that disagrees with the states around it is
// exactly what several denials are about.
type sessionBindingInputs struct {
	authority   domain.AuthorityID
	epoch       domain.AuthorityEpoch
	workspace   domain.WorkspaceID
	principal   domain.PrincipalID
	actor       domain.ActorID
	membership  domain.AggregateRef
	delegation  domain.AggregateRef
	device      *domain.AggregateRef
	deviceTrust domain.Version
	grants      []domain.AggregateRef
	policy      domain.PolicyRevision
	assurance   domain.AssuranceClass
	issuedAt    time.Time
	expiry      time.Time
}

type authorizationSubject struct {
	locked         application.CommandContext
	authentication application.AuthenticationEvidence
	policy         application.PreparedPolicy
	authorization  *LockedAuthorization
}

func authorizationID[ID any](t *testing.T, parse func(string) (ID, error), index int) ID {
	t.Helper()
	value, err := parse(proofUUID(index))
	if err != nil {
		t.Fatalf("parse identifier %d: %v", index, err)
	}
	return value
}

// acceptedWorkspaceAuthorization is the workspace-scoped graph every workspace
// denial starts from: an active principal in a trusted device's installation,
// one active grant, an active workspace and membership, and an active actor
// session bound to all of them.
func acceptedWorkspaceAuthorization(t *testing.T) authorizationInputs {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	installation := authorizationID(t, domain.ParseInstallationID, 200)
	principal := authorizationID(t, domain.ParsePrincipalID, 201)
	device := authorizationID(t, domain.ParseDeviceID, 202)
	workspace := authorizationID(t, domain.ParseWorkspaceID, 203)
	membership := authorizationID(t, domain.ParseMembershipID, 204)
	grant := authorizationID(t, domain.ParseGrantID, 205)
	actor := authorizationID(t, domain.ParseActorID, 206)
	delegation := authorizationID(t, domain.ParseActorDelegationID, 207)
	session := authorizationID(t, domain.ParseActorSessionID, 208)
	authority := authorizationID(t, domain.ParseAuthorityID, 209)
	epoch := authorizationID(t, domain.ParseAuthorityEpoch, 210)
	activation := authorizationID(t, domain.ParseCeremonyID, 211)
	client := authorizationID(t, domain.ParseClientInstanceID, 215)
	workReference := authorizationID(t, domain.ParseWorkReferenceID, 217)

	displayName, err := domain.NewDisplayName("Authorization Subject")
	if err != nil {
		t.Fatal(err)
	}
	keyReference, err := domain.NewPublicKeyReference("keyref:authorization-device")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := domain.NewWorkspaceAlias("authorization-workspace")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := domain.NewActorProfile(displayName)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := domain.NewClientMetadata("blackbird-test", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := domain.NewPolicyRevision("authorization-policy:v1")
	if err != nil {
		t.Fatal(err)
	}
	assurance, err := domain.NewAssuranceClass("hardware_key")
	if err != nil {
		t.Fatal(err)
	}
	audience, err := domain.NewCredentialAudience("blackbird:local")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := domain.NewCredentialDigest(sha256.Sum256([]byte("authorization device spki")))
	if err != nil {
		t.Fatal(err)
	}
	transcript := domain.FingerprintCommand([]byte("authorization device pairing transcript"))
	credential, err := domain.NewDeviceCredentialBinding(keyReference, fingerprint, transcript)
	if err != nil {
		t.Fatal(err)
	}
	credentialReference, err := domain.NewCredentialReference("presentation:authorization-fixture")
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := domain.NewPresentationCredentialBinding(
		fingerprint, credentialReference, audience, domain.PresentationCredentialVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := domain.NewCapabilitySet(
		domain.WorkspaceOwnerCapability(), domain.MembershipAdminCapability(),
	)
	if err != nil {
		t.Fatal(err)
	}
	activationChallenge, err := domain.RehydrateCeremonyChallenge(domain.CeremonyChallengeRehydrationParams{
		ID: activation, Purpose: domain.CeremonyPurposeDelegationActivation,
		ProofDigest: domain.FingerprintCommand([]byte("delegation activation proof")),
		ExpiresAt:   now.Add(time.Hour), Status: domain.CeremonyConsumed,
		WorkspaceID: workspace, PrincipalID: principal, ActorID: actor, DelegationID: delegation,
	})
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := application.NewAuditProvenanceEvidence(authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := domain.WorkspaceScope(workspace)
	if err != nil {
		t.Fatal(err)
	}

	mutated, err := domain.NewVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	initial := domain.InitialVersion()
	membershipRef, err := domain.NewAggregateRef(membership, initial)
	if err != nil {
		t.Fatal(err)
	}
	delegationRef, err := domain.NewAggregateRef(delegation, mutated)
	if err != nil {
		t.Fatal(err)
	}
	deviceRef, err := domain.NewAggregateRef(device, mutated)
	if err != nil {
		t.Fatal(err)
	}
	grantRef, err := domain.NewAggregateRef(grant, initial)
	if err != nil {
		t.Fatal(err)
	}

	return authorizationInputs{
		now: now, installation: installation, authority: authority, epoch: epoch,
		clientID: client, workReference: workReference,
		createdID:   authorizationID(t, domain.ParsePrincipalID, 218),
		assurance:   assurance,
		guardPolicy: policy, preparedPolicy: policy,
		policyDigest: application.DigestBytes([]byte("authorization policy")),
		principal: domain.PrincipalRehydrationParams{
			ID: principal, InstallationID: installation, Kind: domain.PrincipalKindHuman,
			DisplayName: displayName, PublicKeyReference: keyReference,
			Status: domain.PrincipalActive, Version: initial,
		},
		device: domain.DeviceRehydrationParams{
			ID: device, InstallationID: installation, PrincipalID: principal,
			DisplayName: displayName, PublicKeyReference: keyReference,
			Status: domain.DeviceTrusted, Version: mutated, TrustRevision: mutated,
			RevocationRevision: initial, CredentialBinding: credential,
			CredentialActivatedAt: now.Add(-time.Hour),
		},
		grant: domain.GrantRehydrationParams{
			ID: grant, InstallationID: installation, PrincipalID: principal,
			Status: domain.GrantActive, Version: initial, Capabilities: capabilities,
		},
		workspace: domain.WorkspaceRehydrationParams{
			ID: workspace, InstallationID: installation, AuthorityID: authority, AuthorityEpoch: epoch,
			Alias: alias, PolicyRevision: policy, Status: domain.WorkspaceActive, Version: initial,
		},
		membership: domain.MembershipRehydrationParams{
			ID: membership, WorkspaceID: workspace, PrincipalID: principal,
			Status: domain.MembershipActive, Version: initial, Capabilities: capabilities,
		},
		actor: domain.ActorRehydrationParams{
			ID: actor, WorkspaceID: workspace, Kind: domain.ActorKindAgent,
			Profile: profile, Status: domain.ActorActive, Version: initial,
		},
		delegation: domain.ActorDelegationRehydrationParams{
			ID: delegation, WorkspaceID: workspace, PrincipalID: principal, ActorID: actor,
			MembershipID: membership, Status: domain.DelegationActive, Version: mutated,
			Capabilities: capabilities, ActivationChallenge: activationChallenge,
		},
		session: domain.ActorSessionRehydrationParams{
			ID: session, ClientInstanceID: client, ClientMetadata: metadata,
			Status: domain.ActorSessionActive, Version: initial, Capabilities: capabilities,
			PresentationCredential: presentation,
		},
		binding: sessionBindingInputs{
			authority: authority, epoch: epoch, workspace: workspace, principal: principal,
			actor: actor, membership: membershipRef, delegation: delegationRef,
			device: &deviceRef, deviceTrust: mutated, grants: []domain.AggregateRef{grantRef},
			policy: policy, assurance: assurance,
			issuedAt: now.Add(-time.Minute), expiry: now.Add(time.Hour),
		},
		request: application.AuthenticationRequestParams{
			Operation: application.CommandObserveWorkRef, Scope: scope, PrincipalID: principal,
			PrincipalRevision: initial, DeviceID: &device, DeviceRevision: mutated,
			DeviceTrustRevision: mutated, DeviceRevokeRevision: initial, CredentialFingerprint: fingerprint,
			ActorSessionID: &session, ActorSessionRevision: initial,
			GrantRevisions: []domain.AggregateRef{grantRef},
			ChannelBinding: application.DigestBytes([]byte("authorization channel")),
			Audience:       audience, AuditProvenance: provenance, VerifiedAt: now.Add(-time.Second),
		},
		workspaceScoped: true, withDevice: true, withGrant: true,
		withMembership: true, withSession: true,
	}
}

// acceptedInstallationAuthorization is the installation-scoped graph: the same
// principal and grant, no workspace, no device and no session, because the
// installation-admin command contract admits exactly one principal and one
// grant as authorization reads.
func acceptedInstallationAuthorization(t *testing.T) authorizationInputs {
	t.Helper()
	inputs := acceptedWorkspaceAuthorization(t)
	scope, err := domain.InstallationScope(inputs.installation)
	if err != nil {
		t.Fatal(err)
	}
	inputs.workspaceScoped, inputs.withDevice, inputs.withMembership, inputs.withSession = false, false, false, false
	inputs.request.Operation = application.CommandRegisterPrincipal
	inputs.request.Scope = scope
	inputs.request.DeviceID = nil
	inputs.request.DeviceRevision = domain.Version{}
	inputs.request.DeviceTrustRevision = domain.Version{}
	inputs.request.DeviceRevokeRevision = domain.Version{}
	inputs.request.CredentialFingerprint = domain.CredentialDigest{}
	inputs.request.ActorSessionID = nil
	inputs.request.ActorSessionRevision = domain.Version{}
	return inputs
}

// lockedState pairs one rehydrated identity state with the versioned reference
// the guard plan must declare for it, because the command context admits a
// state only when the plan already named it at that exact version.
type lockedState struct {
	state application.IdentityState
	ref   domain.AggregateRef
}

func (inputs authorizationInputs) states(t *testing.T) []lockedState {
	t.Helper()
	states := make([]lockedState, 0, 7)
	add := func(value any, ref domain.AggregateRef, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("aggregate reference for %T: %v", value, err)
		}
		state, stateErr := application.NewIdentityState(value)
		if stateErr != nil {
			t.Fatalf("identity state %T: %v", value, stateErr)
		}
		states = append(states, lockedState{state: state, ref: ref})
	}
	if !inputs.withoutPrincipal {
		principal, principalErr := domain.RehydratePrincipal(inputs.principal)
		if principalErr != nil {
			t.Fatalf("rehydrate principal: %v", principalErr)
		}
		ref, refErr := domain.NewAggregateRef(inputs.principal.ID, principal.Version())
		add(principal, ref, refErr)
	}
	if inputs.withDevice {
		device, deviceErr := domain.RehydrateDevice(inputs.device)
		if deviceErr != nil {
			t.Fatalf("rehydrate device: %v", deviceErr)
		}
		ref, refErr := domain.NewAggregateRef(inputs.device.ID, device.Version())
		add(device, ref, refErr)
	}
	if inputs.withGrant {
		grant, grantErr := domain.RehydrateGrant(inputs.grant)
		if grantErr != nil {
			t.Fatalf("rehydrate grant: %v", grantErr)
		}
		ref, refErr := domain.NewAggregateRef(inputs.grant.ID, grant.Version())
		add(grant, ref, refErr)
	}
	if inputs.workspaceScoped && !inputs.withoutWorkspaceState {
		workspace, workspaceErr := domain.RehydrateWorkspace(inputs.workspace)
		if workspaceErr != nil {
			t.Fatalf("rehydrate workspace: %v", workspaceErr)
		}
		ref, refErr := domain.NewAggregateRef(inputs.workspace.ID, workspace.Version())
		add(workspace, ref, refErr)
	}
	if inputs.withMembership {
		membership, membershipErr := domain.RehydrateMembership(inputs.membership)
		if membershipErr != nil {
			t.Fatalf("rehydrate membership: %v", membershipErr)
		}
		ref, refErr := domain.NewAggregateRef(inputs.membership.ID, membership.Version())
		add(membership, ref, refErr)
	}
	if inputs.withSession {
		actor, actorErr := domain.RehydrateActor(inputs.actor)
		if actorErr != nil {
			t.Fatalf("rehydrate actor: %v", actorErr)
		}
		actorRef, actorRefErr := domain.NewAggregateRef(inputs.actor.ID, actor.Version())
		add(actor, actorRef, actorRefErr)
		delegation, delegationErr := domain.RehydrateActorDelegation(inputs.delegation)
		if delegationErr != nil {
			t.Fatalf("rehydrate delegation: %v", delegationErr)
		}
		delegationRef, delegationRefErr := domain.NewAggregateRef(inputs.delegation.ID, delegation.Version())
		add(delegation, delegationRef, delegationRefErr)
		sessionParams := inputs.session
		sessionParams.Binding = inputs.binding.build(t)
		session, sessionErr := domain.RehydrateActorSession(sessionParams)
		if sessionErr != nil {
			t.Fatalf("rehydrate actor session: %v", sessionErr)
		}
		sessionRef, sessionRefErr := domain.NewAggregateRef(inputs.session.ID, session.Version())
		add(session, sessionRef, sessionRefErr)
	}
	return states
}

func (binding sessionBindingInputs) build(t *testing.T) domain.SessionBinding {
	t.Helper()
	value, err := domain.NewSessionBinding(
		binding.authority, binding.epoch, binding.workspace, binding.principal, binding.actor,
		binding.membership, binding.delegation, binding.device, binding.deviceTrust,
		binding.grants, binding.policy, binding.assurance, binding.issuedAt, binding.expiry,
	)
	if err != nil {
		t.Fatalf("session binding: %v", err)
	}
	return value
}

func (inputs authorizationInputs) build(t *testing.T) authorizationSubject {
	t.Helper()
	locked := inputs.states(t)
	spec := inputs.spec(t, locked)
	guardEvidence, err := application.NewAppliedGuardEvidence(spec.Guards(), spec.Guards().Evidence())
	if err != nil {
		t.Fatalf("applied guard evidence: %v", err)
	}
	states := make([]application.IdentityState, 0, len(locked))
	for _, entry := range locked {
		states = append(states, entry.state)
	}
	resolution := application.AdmitReceipt()
	timeEvidence, err := application.PersistedCommandAuthorityTime(inputs.now)
	if err != nil {
		t.Fatal(err)
	}
	if inputs.withoutAuthorityTime {
		states = nil
		resolution, err = application.ConflictReceipt(application.ReceiptIntegrityConflict, domain.ReceiptID{})
		if err != nil {
			t.Fatal(err)
		}
		timeEvidence, err = application.ReadOnlyDisclosureTime(inputs.now, inputs.now)
		if err != nil {
			t.Fatal(err)
		}
	}
	commandContext, err := application.NewCommandContext(spec, timeEvidence, states, resolution, guardEvidence)
	if err != nil {
		t.Fatalf("command context: %v", err)
	}
	request, err := application.NewAuthenticationRequest(inputs.request)
	if err != nil {
		t.Fatalf("authentication request: %v", err)
	}
	authentication, err := application.NewAuthenticationEvidence(request)
	if err != nil {
		t.Fatalf("authentication evidence: %v", err)
	}
	policy, err := application.NewPreparedPolicy(inputs.preparedPolicy, inputs.policyDigest)
	if err != nil {
		t.Fatalf("prepared policy: %v", err)
	}
	authorization, err := NewLockedAuthorization(inputs.assurance, domain.MaxActorSessionLifetime)
	if err != nil {
		t.Fatalf("locked authorization: %v", err)
	}
	return authorizationSubject{
		locked: commandContext, authentication: authentication, policy: policy, authorization: authorization,
	}
}

func (inputs authorizationInputs) spec(t *testing.T, locked []lockedState) application.CommandSpec {
	t.Helper()
	operation := application.CommandObserveWorkRef
	if !inputs.workspaceScoped {
		operation = application.CommandRegisterPrincipal
	}
	name, err := domain.NewOperationName(string(operation))
	if err != nil {
		t.Fatal(err)
	}
	major, err := application.NewOperationMajor(1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := domain.NewIdempotencyKey("authorization-fixture")
	if err != nil {
		t.Fatal(err)
	}
	scope := inputs.commandScope(t)
	receipt := inputs.receiptIdentity(t, scope, name, key)
	authorship, err := application.AuthorityAuthorship(inputs.principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := application.NewGuardGeneration(11)
	if err != nil {
		t.Fatal(err)
	}
	epochGuard, err := application.CurrentAuthorityEpochGuard(scope, inputs.authority, inputs.epoch)
	if err != nil {
		t.Fatal(err)
	}
	policyGuard, err := application.PolicyRevisionGuard(scope, inputs.guardPolicy)
	if err != nil {
		t.Fatal(err)
	}
	principalTarget, err := domain.NewAggregateTarget(inputs.principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	authorizations := make([]domain.AggregateRef, 0, len(locked))
	for _, entry := range locked {
		authorizations = append(authorizations, entry.ref)
	}
	planParams := application.CommandGuardPlanParams{
		AdmissionScope: scope, AdmissionGeneration: generation,
		Evidence:      []application.EvidenceGuard{epochGuard, policyGuard},
		Authorization: authorizations,
		Disclosure:    []domain.AggregateTarget{principalTarget},
	}
	factType := domain.EventTypeWorkRefObserved
	origin, err := domain.NewAggregateRef(inputs.workReference, domain.InitialVersion())
	if err != nil {
		t.Fatal(err)
	}
	capsule := application.NotApplicableRecoveryCapsulePlan()
	if !inputs.workspaceScoped {
		factType = domain.EventTypePrincipalRegistered
		mutationTarget, targetErr := domain.NewAggregateTarget(inputs.createdID)
		if targetErr != nil {
			t.Fatal(targetErr)
		}
		planParams.Disclosure = append(planParams.Disclosure, mutationTarget)
		origin, err = domain.NewAggregateRef(inputs.createdID, domain.InitialVersion())
		if err != nil {
			t.Fatal(err)
		}
		grantTarget, targetErr := domain.NewAggregateTarget(inputs.grant.ID)
		if targetErr != nil {
			t.Fatal(targetErr)
		}
		ceiling, ceilingErr := application.CapabilityCeilingGuard(
			grantTarget, application.DigestBytes([]byte("grant ceiling")),
		)
		if ceilingErr != nil {
			t.Fatal(ceilingErr)
		}
		planParams.Evidence = append(planParams.Evidence, inputs.lifecycleGuards(t, locked)...)
		planParams.Evidence = append(planParams.Evidence, ceiling)
	}
	mutation, err := domain.ExpectAggregateAbsent(inputs.workReference)
	if !inputs.workspaceScoped {
		mutation, err = domain.ExpectAggregateAbsent(inputs.createdID)
	}
	if err != nil {
		t.Fatal(err)
	}
	planParams.Mutations = []domain.AggregateExpectation{mutation}
	plan, err := application.NewCommandGuardPlan(planParams)
	if err != nil {
		t.Fatalf("guard plan: %v", err)
	}
	if !inputs.workspaceScoped {
		capsule, err = application.PrepareRecoveryCapsulePlan(stubCapsuleSigner{})
		if err != nil {
			t.Fatal(err)
		}
	}
	fact, err := application.NewFactExpectation(
		authorizationID(t, domain.ParseEventID, 216), factType, origin,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := application.NewCommandSpec(application.CommandSpecParams{
		Scope: scope, AuthorityID: inputs.authority, RequestedEpoch: inputs.epoch,
		CommandID: authorizationID(t, domain.ParseCommandID, 212),
		ReceiptID: authorizationID(t, domain.ParseReceiptID, 213),
		Operation: name, OperationMajor: major, ReceiptIdentity: receipt,
		RequestFingerprint: domain.FingerprintCommand([]byte("authorization fixture command")),
		Authorship:         authorship,
		CorrelationID:      authorizationID(t, domain.ParseCorrelationID, 214),
		AuthorityTimeClass: application.AuthorityTimeOrdinary, RecoveryCapsule: capsule,
		Guards: plan, ExpectedFacts: []application.FactExpectation{fact},
	})
	if err != nil {
		t.Fatalf("command spec: %v", err)
	}
	return spec
}

func (inputs authorizationInputs) commandScope(t *testing.T) domain.AuthorityScope {
	t.Helper()
	if inputs.workspaceScoped {
		scope, err := domain.WorkspaceScope(inputs.workspace.ID)
		if err != nil {
			t.Fatal(err)
		}
		return scope
	}
	scope, err := domain.InstallationScope(inputs.installation)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func (inputs authorizationInputs) receiptIdentity(
	t *testing.T,
	scope domain.AuthorityScope,
	name domain.OperationName,
	key domain.IdempotencyKey,
) application.ReceiptIdentity {
	t.Helper()
	if !inputs.workspaceScoped {
		receipt, err := application.InstallationAdminReceiptIdentity(
			inputs.installation, inputs.principal.ID, inputs.clientID, name, key,
		)
		if err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	workspace, err := domain.ParseWorkspaceID(scope.ID())
	if err != nil {
		t.Fatal(err)
	}
	idempotency, err := domain.NewIdempotencyScope(workspace, inputs.principal.ID, inputs.clientID, name, key)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := application.OrdinaryReceiptIdentity(idempotency)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func (inputs authorizationInputs) lifecycleGuards(
	t *testing.T,
	locked []lockedState,
) []application.EvidenceGuard {
	t.Helper()
	statuses := map[domain.AggregateKind]string{
		domain.AggregateKindPrincipal: string(inputs.principal.Status),
		domain.AggregateKindGrant:     string(inputs.grant.Status),
	}
	guards := make([]application.EvidenceGuard, 0, len(locked))
	for _, entry := range locked {
		status, known := statuses[entry.state.Target().Kind()]
		if !known {
			continue
		}
		guard, err := application.LifecycleStatusGuard(entry.state.Target(), status)
		if err != nil {
			t.Fatal(err)
		}
		guards = append(guards, guard)
	}
	return guards
}

// stubCapsuleSigner satisfies the recovery-capsule plan for command specs that
// declare one. Authorization never signs, so the key identity is enough.
type stubCapsuleSigner struct{}

func (stubCapsuleSigner) KeyID() string { return "ed25519:authorization-fixture" }

func (stubCapsuleSigner) Ed25519PublicKey() ed25519.PublicKey {
	seed := sha256.Sum256([]byte("authorization fixture capsule key"))
	return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
}

func (stubCapsuleSigner) SignRecoveryCapsule(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("authorization fixture never signs")
}

func TestAuthorizeLockedGrantsScopedIdentityAuthorization(t *testing.T) {
	t.Parallel()

	installationInputs := acceptedInstallationAuthorization(t)
	installation := installationInputs.build(t)
	granted, err := installation.authorization.AuthorizeLocked(
		installation.locked, installation.authentication, installation.policy,
	)
	if err != nil {
		t.Fatalf("installation AuthorizeLocked: %v", err)
	}
	if granted.InstallationID() != installationInputs.installation ||
		granted.PrincipalID() != installationInputs.principal.ID ||
		!granted.WorkspaceID().IsZero() || granted.PolicyRevision() != installationInputs.preparedPolicy ||
		granted.AssuranceClass() != installationInputs.assurance {
		t.Fatalf("installation authorization = %+v", granted)
	}
	if _, _, bound := granted.AuthenticatedDevice(); bound {
		t.Fatal("installation-scoped authorization reported an authenticated device")
	}

	workspaceInputs := acceptedWorkspaceAuthorization(t)
	workspace := workspaceInputs.build(t)
	granted, err = workspace.authorization.AuthorizeLocked(
		workspace.locked, workspace.authentication, workspace.policy,
	)
	if err != nil {
		t.Fatalf("workspace AuthorizeLocked: %v", err)
	}
	if granted.WorkspaceID() != workspaceInputs.workspace.ID ||
		granted.InstallationID() != workspaceInputs.installation ||
		granted.PrincipalID() != workspaceInputs.principal.ID ||
		granted.AssuranceClass() != workspaceInputs.binding.assurance {
		t.Fatalf("workspace authorization = %+v", granted)
	}
	device, trust, bound := granted.AuthenticatedDevice()
	if !bound || device != workspaceInputs.device.ID || trust != workspaceInputs.device.TrustRevision {
		t.Fatalf("device binding = (%v, %v, %v)", device, trust, bound)
	}
	// The session narrows the identity to the capabilities every set shares.
	for _, capability := range granted.Capabilities().Values() {
		if !workspaceInputs.grant.Capabilities.Contains(capability) {
			t.Fatalf("granted capability %q is outside the installation grant", capability)
		}
	}

	unbound := acceptedWorkspaceAuthorization(t)
	unbound.withDevice, unbound.withSession = false, false
	unbound.request.DeviceID = nil
	unbound.request.DeviceRevision = domain.Version{}
	unbound.request.DeviceTrustRevision = domain.Version{}
	unbound.request.DeviceRevokeRevision = domain.Version{}
	unbound.request.CredentialFingerprint = domain.CredentialDigest{}
	unbound.request.ActorSessionID = nil
	unbound.request.ActorSessionRevision = domain.Version{}
	subject := unbound.build(t)
	granted, err = subject.authorization.AuthorizeLocked(subject.locked, subject.authentication, subject.policy)
	if err != nil {
		t.Fatalf("device-free workspace AuthorizeLocked: %v", err)
	}
	if _, _, bound := granted.AuthenticatedDevice(); bound {
		t.Fatal("device-free request produced a device-bound authorization")
	}
	if granted.AssuranceClass() != unbound.assurance {
		t.Fatalf("session-free assurance = %v, want the configured class", granted.AssuranceClass())
	}
}

// TestAuthorizeLockedDeniesEveryUnsatisfiedPredicate pins one denial per
// authorization predicate. Each case spoils exactly one input of an otherwise
// accepted graph, so a predicate that stops being checked shows up here as a
// request that is suddenly authorized.
func TestAuthorizeLockedDeniesEveryUnsatisfiedPredicate(t *testing.T) {
	t.Parallel()

	otherPrincipal := authorizationID(t, domain.ParsePrincipalID, 250)
	otherInstallation := authorizationID(t, domain.ParseInstallationID, 251)
	otherWorkspace := authorizationID(t, domain.ParseWorkspaceID, 252)
	otherAuthority := authorizationID(t, domain.ParseAuthorityID, 253)
	otherEpoch := authorizationID(t, domain.ParseAuthorityEpoch, 254)
	otherActor := authorizationID(t, domain.ParseActorID, 255)
	otherMembership := authorizationID(t, domain.ParseMembershipID, 256)
	otherRevision, err := domain.NewPolicyRevision("authorization-policy:v2")
	if err != nil {
		t.Fatal(err)
	}
	otherAudience, err := domain.NewCredentialAudience("blackbird:other")
	if err != nil {
		t.Fatal(err)
	}
	otherFingerprint, err := domain.NewCredentialDigest(sha256.Sum256([]byte("other device spki")))
	if err != nil {
		t.Fatal(err)
	}
	disjoint, err := domain.NewCapabilitySet(domain.DevicePairCapability())
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := domain.NewVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := domain.NewVersion(3)
	if err != nil {
		t.Fatal(err)
	}
	installationScope, err := domain.InstallationScope(
		authorizationID(t, domain.ParseInstallationID, 200),
	)
	if err != nil {
		t.Fatal(err)
	}

	spoilers := map[string]authorizationSpoiler{
		"authority time absent": {reason: DenialAuthorityTimeAbsent, spoil: func(inputs *authorizationInputs) {
			inputs.withoutAuthorityTime = true
		}},
		"authentication verified after authority time": {reason: DenialRequestUnbound, spoil: func(inputs *authorizationInputs) {
			inputs.request.VerifiedAt = inputs.now.Add(time.Hour)
		}},
		"authentication bound to another scope": {reason: DenialRequestUnbound, spoil: func(inputs *authorizationInputs) {
			inputs.request.Scope = installationScope
		}},
		"authentication bound to another operation": {reason: DenialRequestUnbound, spoil: func(inputs *authorizationInputs) {
			inputs.request.Operation = application.CommandActivateObjective
		}},
		"authentication bound to another principal": {reason: DenialRequestUnbound, spoil: func(inputs *authorizationInputs) {
			inputs.request.PrincipalID = otherPrincipal
		}},
		"principal state absent": {reason: DenialPrincipalUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.withoutPrincipal = true
		}},
		"principal suspended": {reason: DenialPrincipalUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.principal.Status = domain.PrincipalSuspended
			inputs.principal.Version = mutated
			inputs.request.PrincipalRevision = mutated
		}},
		"principal revision stale": {reason: DenialPrincipalUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.principal.Version = mutated
		}},
		"device state absent": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.withDevice = false
		}},
		"device suspended": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.device.Status = domain.DeviceSuspended
		}},
		"device belongs to another principal": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.device.PrincipalID = otherPrincipal
		}},
		"device belongs to another installation": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.device.InstallationID = otherInstallation
		}},
		"device revision stale": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.request.DeviceRevision = advanced
		}},
		"device trust revision stale": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.request.DeviceTrustRevision = advanced
		}},
		"device revocation revision stale": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.request.DeviceRevokeRevision = mutated
		}},
		"device credential not accepted": {reason: DenialDeviceUntrusted, spoil: func(inputs *authorizationInputs) {
			inputs.request.CredentialFingerprint = otherFingerprint
		}},
		"grant state absent": {reason: DenialGrantUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.withGrant = false
		}},
		"grant revoked": {reason: DenialGrantUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.grant.Status = domain.GrantRevoked
			inputs.grant.Version = mutated
			inputs.refreshGrantRevision(t, mutated)
		}},
		"grant revision stale": {reason: DenialGrantUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.grant.Version = mutated
		}},
		"grant belongs to another principal": {reason: DenialGrantUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.grant.PrincipalID = otherPrincipal
		}},
		"grant belongs to another installation": {reason: DenialGrantUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.grant.InstallationID = otherInstallation
		}},
		"grant scoped to another workspace": {reason: DenialGrantUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.grant.WorkspaceID = otherWorkspace
		}},
		"workspace state absent": {reason: DenialWorkspaceUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.withoutWorkspaceState = true
		}},
		"workspace suspended": {reason: DenialWorkspaceUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.workspace.Status = domain.WorkspaceSuspended
			inputs.workspace.Version = mutated
		}},
		"workspace belongs to another installation": {reason: DenialWorkspaceUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.workspace.InstallationID = otherInstallation
		}},
		"workspace under another authority": {reason: DenialWorkspaceUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.workspace.AuthorityID = otherAuthority
		}},
		"workspace under another epoch": {reason: DenialWorkspaceUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.workspace.AuthorityEpoch = otherEpoch
		}},
		"workspace policy revision differs from prepared policy": {reason: DenialWorkspaceUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.preparedPolicy = otherRevision
		}},
		"membership suspended": {reason: DenialMembershipUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.membership.Status = domain.MembershipSuspended
			inputs.membership.Version = mutated
		}},
		"membership in another workspace": {reason: DenialMembershipUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.membership.WorkspaceID = otherWorkspace
		}},
		"actor session state absent": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.withSession = false
		}},
		"actor session revision stale": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.session.Version = mutated
		}},
		"actor session ended": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.session.Status = domain.ActorSessionEnded
			inputs.session.Version = mutated
			inputs.request.ActorSessionRevision = mutated
		}},
		"actor session past absolute expiry": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.binding.expiry = inputs.now
		}},
		"session bound to another principal": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.binding.principal = otherPrincipal
		}},
		"session bound to another workspace": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.binding.workspace = otherWorkspace
		}},
		"session bound to another authority": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.binding.authority = otherAuthority
		}},
		"session bound to another epoch": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.binding.epoch = otherEpoch
		}},
		"session bound to another policy revision": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.binding.policy = otherRevision
		}},
		"presentation credential issued for another audience": {reason: DenialSessionUnusable, spoil: func(inputs *authorizationInputs) {
			inputs.request.Audience = otherAudience
		}},
		"session membership reference stale": {reason: DenialSessionReferencesStale, spoil: func(inputs *authorizationInputs) {
			inputs.binding.membership = mustRef(t, inputs.membership.ID, mutated)
		}},
		"session delegation reference stale": {reason: DenialSessionReferencesStale, spoil: func(inputs *authorizationInputs) {
			inputs.binding.delegation = mustRef(t, inputs.delegation.ID, domain.InitialVersion())
		}},
		"session delegation revoked": {reason: DenialSessionReferencesStale, spoil: func(inputs *authorizationInputs) {
			inputs.delegation.Status = domain.DelegationRevoked
		}},
		"session actor absent": {reason: DenialSessionReferencesStale, spoil: func(inputs *authorizationInputs) {
			inputs.binding.actor = otherActor
		}},
		"session actor suspended": {reason: DenialSessionReferencesStale, spoil: func(inputs *authorizationInputs) {
			inputs.actor.Status = domain.ActorSuspended
			inputs.actor.Version = mutated
		}},
		"delegation attached to another membership": {reason: DenialSessionReferencesStale, spoil: func(inputs *authorizationInputs) {
			inputs.delegation.MembershipID = otherMembership
		}},
		"session device reference stale": {reason: DenialSessionDeviceStale, spoil: func(inputs *authorizationInputs) {
			inputs.binding.device = mustRefPointer(t, inputs.device.ID, advanced)
		}},
		"session device trust revision stale": {reason: DenialSessionDeviceStale, spoil: func(inputs *authorizationInputs) {
			inputs.binding.deviceTrust = advanced
		}},
		"session grant references differ from the request": {reason: DenialSessionGrantsStale, spoil: func(inputs *authorizationInputs) {
			inputs.binding.grants = nil
		}},
		"capability intersection empty": {reason: DenialCapabilitiesEmpty, spoil: func(inputs *authorizationInputs) {
			inputs.membership.Capabilities = disjoint
		}},
	}

	for name, spoiler := range spoilers {
		t.Run(name, func(t *testing.T) {
			inputs := acceptedWorkspaceAuthorization(t)
			spoiler.spoil(&inputs)
			subject := inputs.build(t)
			granted, authorizeErr := subject.authorization.AuthorizeLocked(
				subject.locked, subject.authentication, subject.policy,
			)
			if !errors.Is(authorizeErr, ErrAccessDenied) {
				t.Fatalf("AuthorizeLocked error = %v, granted %+v", authorizeErr, granted)
			}
			var denial *AccessDenialError
			if !errors.As(authorizeErr, &denial) || denial.Reason() != spoiler.reason {
				t.Fatalf("denial reason = %q, want %q", denial.Reason(), spoiler.reason)
			}
			// A denial must reach the transport as an authorization failure.
			// A bare sentinel is reclassified as a retryable INTERNAL, which
			// tells the agent to retry a request that can never succeed.
			var rejection *domain.CommandError
			if !errors.As(authorizeErr, &rejection) {
				t.Fatalf("denial is not a domain command error: %v", authorizeErr)
			}
			wantCode := domain.ErrorCodeForbidden
			if spoiler.reason == DenialCapabilitiesEmpty {
				wantCode = domain.ErrorCodeCapabilityRequired
			}
			if rejection.Code() != wantCode || rejection.Category() != domain.ErrorCategoryAuthorization ||
				rejection.Retryable() {
				t.Fatalf("rejection = (%s, %s, retryable %t)",
					rejection.Code(), rejection.Category(), rejection.Retryable())
			}
			if strings.Contains(rejection.Message(), string(spoiler.reason)) {
				t.Fatalf("caller-facing message disclosed the denial predicate: %q", rejection.Message())
			}
		})
	}
}

// authorizationSpoiler is one accepted input made unacceptable, together with
// the predicate that must be the one to notice.
type authorizationSpoiler struct {
	reason DenialReason
	spoil  func(*authorizationInputs)
}

func TestAuthorizeLockedDeniesUnusableDependencies(t *testing.T) {
	t.Parallel()

	inputs := acceptedWorkspaceAuthorization(t)
	subject := inputs.build(t)
	assurance, err := domain.NewAssuranceClass("hardware_key")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := application.NewPreparedPolicy(inputs.preparedPolicy, inputs.policyDigest)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		authorization *LockedAuthorization
		policy        application.PreparedPolicy
	}{
		"nil authorization":        {authorization: nil, policy: prepared},
		"unconfigured assurance":   {authorization: &LockedAuthorization{}, policy: prepared},
		"unprepared policy":        {authorization: subject.authorization, policy: application.PreparedPolicy{}},
		"configured but no policy": {authorization: &LockedAuthorization{assurance: assurance}, policy: application.PreparedPolicy{}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := test.authorization.AuthorizeLocked(
				subject.locked, subject.authentication, test.policy,
			); !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("AuthorizeLocked error = %v", err)
			}
		})
	}

	if _, err := NewReplayAuthorization(nil); !errors.Is(err, ErrSecurityDependency) {
		t.Fatalf("NewReplayAuthorization(nil) error = %v", err)
	}
	replay, err := NewReplayAuthorization(subject.authorization)
	if err != nil {
		t.Fatal(err)
	}
	// An admitted command is not an exact replay, so disclosure is refused
	// before any identity state is read.
	for name, disclosure := range map[string]*ReplayAuthorization{
		"admitted command": replay,
		"uninitialized":    nil,
	} {
		t.Run("replay refused: "+name, func(t *testing.T) {
			_, replayErr := disclosure.AuthorizeReplay(subject.locked, subject.authentication, subject.policy)
			if !errors.Is(replayErr, ErrAccessDenied) {
				t.Fatalf("AuthorizeReplay error = %v", replayErr)
			}
			// The application layer accepts only FORBIDDEN for an exact-replay
			// resolution, so a disclosure refusal must never report
			// CAPABILITY_REQUIRED.
			var rejection *domain.CommandError
			if !errors.As(replayErr, &rejection) || rejection.Code() != domain.ErrorCodeForbidden {
				t.Fatalf("AuthorizeReplay rejection = %v", replayErr)
			}
		})
	}
}

func TestIntersectCapabilitiesKeepsOnlySharedCapabilities(t *testing.T) {
	t.Parallel()

	owner, err := domain.NewCapabilitySet(
		domain.WorkspaceOwnerCapability(), domain.MembershipAdminCapability(), domain.ActorAdminCapability(),
	)
	if err != nil {
		t.Fatal(err)
	}
	delegated, err := domain.NewCapabilitySet(
		domain.MembershipAdminCapability(), domain.ActorAdminCapability(),
	)
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.NewCapabilitySet(domain.ActorAdminCapability())
	if err != nil {
		t.Fatal(err)
	}
	disjoint, err := domain.NewCapabilitySet(domain.DevicePairCapability())
	if err != nil {
		t.Fatal(err)
	}

	shared, err := intersectCapabilities([]domain.CapabilitySet{owner, delegated, session})
	if err != nil {
		t.Fatalf("intersectCapabilities: %v", err)
	}
	if len(shared.Values()) != 1 || !shared.Contains(domain.ActorAdminCapability()) {
		t.Fatalf("intersection = %v", shared.Values())
	}
	if _, err := intersectCapabilities(nil); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("empty set list error = %v", err)
	}
	if _, err := intersectCapabilities([]domain.CapabilitySet{owner, disjoint}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("disjoint intersection error = %v", err)
	}
}

func TestSameAggregateRefsComparesOrderAndLength(t *testing.T) {
	t.Parallel()

	grant := authorizationID(t, domain.ParseGrantID, 205)
	other := authorizationID(t, domain.ParseGrantID, 260)
	first := mustRef(t, grant, domain.InitialVersion())
	second := mustRef(t, other, domain.InitialVersion())
	advanced, err := domain.NewVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	rotated := mustRef(t, grant, advanced)

	if !sameAggregateRefs(nil, nil) {
		t.Fatal("two empty reference lists compared unequal")
	}
	if !sameAggregateRefs([]domain.AggregateRef{first, second}, []domain.AggregateRef{first, second}) {
		t.Fatal("identical reference lists compared unequal")
	}
	if sameAggregateRefs([]domain.AggregateRef{first}, []domain.AggregateRef{first, second}) {
		t.Fatal("reference lists of different length compared equal")
	}
	if sameAggregateRefs([]domain.AggregateRef{first}, []domain.AggregateRef{rotated}) {
		t.Fatal("reference lists at different versions compared equal")
	}
}

func mustRef(t *testing.T, id interface{ String() string }, version domain.Version) domain.AggregateRef {
	t.Helper()
	var (
		ref domain.AggregateRef
		err error
	)
	switch value := id.(type) {
	case domain.MembershipID:
		ref, err = domain.NewAggregateRef(value, version)
	case domain.ActorDelegationID:
		ref, err = domain.NewAggregateRef(value, version)
	case domain.DeviceID:
		ref, err = domain.NewAggregateRef(value, version)
	case domain.GrantID:
		ref, err = domain.NewAggregateRef(value, version)
	default:
		t.Fatalf("unsupported reference identifier %T", id)
	}
	if err != nil {
		t.Fatalf("aggregate reference: %v", err)
	}
	return ref
}

func mustRefPointer(t *testing.T, id interface{ String() string }, version domain.Version) *domain.AggregateRef {
	t.Helper()
	ref := mustRef(t, id, version)
	return &ref
}

// refreshGrantRevision keeps the request and the session binding pointing at the
// grant's current version, so a case about the grant's status is not decided by
// a version mismatch it did not intend.
func (inputs *authorizationInputs) refreshGrantRevision(t *testing.T, version domain.Version) {
	t.Helper()
	ref := mustRef(t, inputs.grant.ID, version)
	inputs.request.GrantRevisions = []domain.AggregateRef{ref}
	inputs.binding.grants = []domain.AggregateRef{ref}
}

// TestStrictDenialPolicyRecordsThePredicateThatRefused proves the two halves of
// the disclosure decision at once: the caller-facing rejection stays generic,
// while the durable denial audit row an operator reads names the predicate.
func TestStrictDenialPolicyRecordsThePredicateThatRefused(t *testing.T) {
	t.Parallel()

	inputs := acceptedWorkspaceAuthorization(t)
	inputs.membership.Status = domain.MembershipSuspended
	mutated, err := domain.NewVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	inputs.membership.Version = mutated
	subject := inputs.build(t)
	_, authorizeErr := subject.authorization.AuthorizeLocked(
		subject.locked, subject.authentication, subject.policy,
	)
	var rejection *domain.CommandError
	if !errors.As(authorizeErr, &rejection) {
		t.Fatalf("AuthorizeLocked error = %v", authorizeErr)
	}

	security, err := StrictDenialSecurityPolicy{}.DenialFollowUp(
		subject.locked, subject.authentication, subject.policy, rejection,
	)
	if err != nil {
		t.Fatalf("DenialFollowUp: %v", err)
	}
	draft, present := security.CommandDenial()
	if !present {
		t.Fatal("denial follow-up produced no command denial draft")
	}
	if draft.Class() != application.DenialAuthorization {
		t.Fatalf("denial class = %q", draft.Class())
	}
	if draft.SafeReason() != string(DenialMembershipUnusable) {
		t.Fatalf("denial reason = %q, want %q", draft.SafeReason(), DenialMembershipUnusable)
	}
	if security.Operation() != application.SecurityRecordCommandDenial ||
		security.Scope() != subject.locked.Spec().Scope() {
		t.Fatalf("security spec = (%v, %v)", security.Operation(), security.Scope())
	}

	// A rejection raised outside this boundary names no predicate and keeps the
	// cataloged class reason rather than inventing one.
	cataloged, err := domain.NewCommandError(domain.ErrorCodeForbidden, "domain transition refused", nil)
	if err != nil {
		t.Fatal(err)
	}
	security, err = StrictDenialSecurityPolicy{}.DenialFollowUp(
		subject.locked, subject.authentication, subject.policy, cataloged,
	)
	if err != nil {
		t.Fatalf("DenialFollowUp for a cataloged rejection: %v", err)
	}
	draft, _ = security.CommandDenial()
	if draft.SafeReason() != "authorization_denied" {
		t.Fatalf("cataloged denial reason = %q", draft.SafeReason())
	}
}

func TestStrictDenialPolicyRejectsUnusableFollowUps(t *testing.T) {
	t.Parallel()

	inputs := acceptedWorkspaceAuthorization(t)
	subject := inputs.build(t)
	forbidden, err := domain.NewCommandError(domain.ErrorCodeForbidden, "denied", nil)
	if err != nil {
		t.Fatal(err)
	}
	notFound, err := domain.NewCommandError(domain.ErrorCodeNotFound, "absent", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := domain.ParsePrincipalID(proofUUID(270))
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := application.NewAuditProvenanceEvidence(inputs.authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := application.NewAuthenticationEvidence(other, (*domain.DeviceID)(nil), provenance)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		authentication application.AuthenticationEvidence
		policy         application.PreparedPolicy
		rejection      *domain.CommandError
	}{
		"no rejection":            {subject.authentication, subject.policy, nil},
		"unprepared policy":       {subject.authentication, application.PreparedPolicy{}, forbidden},
		"unattributed principal":  {application.AuthenticationEvidence{}, subject.policy, forbidden},
		"another principal":       {foreign, subject.policy, forbidden},
		"uncataloged denial code": {subject.authentication, subject.policy, notFound},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (StrictDenialSecurityPolicy{}).DenialFollowUp(
				subject.locked, test.authentication, test.policy, test.rejection,
			); !errors.Is(err, application.ErrInvalidSecuritySpec) {
				t.Fatalf("DenialFollowUp error = %v", err)
			}
		})
	}
}

func TestAccessDenialNamesThePredicateAndStaysMatchable(t *testing.T) {
	t.Parallel()

	denial := &AccessDenialError{reason: DenialDeviceUntrusted}
	if !errors.Is(denial, ErrAccessDenied) {
		t.Fatal("a named denial no longer matches the local access sentinel")
	}
	if denial.Reason() != DenialDeviceUntrusted ||
		!strings.Contains(denial.Error(), string(DenialDeviceUntrusted)) ||
		!strings.Contains(denial.Error(), ErrAccessDenied.Error()) {
		t.Fatalf("denial text = %q", denial.Error())
	}
	var unnamed *AccessDenialError
	if unnamed.Reason() != "" || unnamed.Error() != ErrAccessDenied.Error() {
		t.Fatalf("unnamed denial = (%q, %q)", unnamed.Reason(), unnamed.Error())
	}
	if (&AccessDenialError{}).Error() != ErrAccessDenied.Error() {
		t.Fatal("a denial with no predicate did not fall back to the sentinel text")
	}
}

func TestStrictDenialPolicyClassifiesAuthenticationFailures(t *testing.T) {
	t.Parallel()

	inputs := acceptedWorkspaceAuthorization(t)
	subject := inputs.build(t)
	for name, code := range map[string]domain.ErrorCode{
		"unauthenticated": domain.ErrorCodeUnauthenticated,
		"session expired": domain.ErrorCodeSessionExpired,
	} {
		t.Run(name, func(t *testing.T) {
			rejection, err := domain.NewCommandError(code, "credential refused", nil)
			if err != nil {
				t.Fatal(err)
			}
			security, err := StrictDenialSecurityPolicy{}.DenialFollowUp(
				subject.locked, subject.authentication, subject.policy, rejection,
			)
			if err != nil {
				t.Fatalf("DenialFollowUp: %v", err)
			}
			draft, present := security.CommandDenial()
			if !present || draft.Class() != application.DenialAuthentication ||
				draft.SafeReason() != "credential_rejected" {
				t.Fatalf("denial draft = (%v, %q, %q)", present, draft.Class(), draft.SafeReason())
			}
		})
	}
}
