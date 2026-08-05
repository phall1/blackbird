package localsecurity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

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
