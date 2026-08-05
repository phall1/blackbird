package localsecurity

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
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
