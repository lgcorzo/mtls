// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"

	"aead.dev/mtls/ssh"
)

// TestGenerateKeyEdDSA tests whether generated EdDSA private keys
// can be wrapped and have the correct identity.
func TestGenerateKeyEdDSA(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EdDSA private key: %v", err)
	}
	key, err := ssh.NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to create private key: %v", err)
	}

	_, ok := key.Private().(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("generated key is not Ed25519PrivateKey")
	}
	if key.Identity().IsZero() {
		t.Fatalf("identity should not be zero")
	}
}

// TestGenerateKeyECDSA tests whether generated ECDSA private keys
// are wrapped correctly for all supported curves.
func TestGenerateKeyECDSA(t *testing.T) {
	t.Parallel()

	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, curve := range curves {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA private key for curve %s: %v", curve.Params().Name, err)
		}
		key, err := ssh.NewPrivateKey(priv)
		if err != nil {
			t.Fatalf("failed to wrap ECDSA private key for curve %s: %v", curve.Params().Name, err)
		}

		privKey, ok := key.Private().(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("generated key is not ECDSA private key")
		}
		if privKey.Curve != curve {
			t.Fatalf("key curve mismatch for %s", curve.Params().Name)
		}
		if key.Identity().IsZero() {
			t.Fatalf("identity should not be zero for curve %s", curve.Params().Name)
		}
	}
}

// TestGenerateKeyRSA tests whether generated RSA private keys
// are wrapped correctly for common key sizes.
func TestGenerateKeyRSA(t *testing.T) {
	t.Parallel()

	bitSizes := []int{2048, 3072, 4096}
	for _, bits := range bitSizes {
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("failed to generate %d RSA private key: %v", bits, err)
		}
		key, err := ssh.NewPrivateKey(priv)
		if err != nil {
			t.Fatalf("failed to wrap %d RSA private key: %v", bits, err)
		}

		privKey, ok := key.Private().(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("generated key is not RSA private key")
		}
		if privKey.N.BitLen() < bits-1 || privKey.N.BitLen() > bits {
			t.Fatalf("key size mismatch for %d bit RSA key", bits)
		}
		if key.Identity().IsZero() {
			t.Fatalf("identity should not be zero for %d bit RSA key", bits)
		}
	}
}

// TestPrivateKey_Identity checks that the identity computed from a private key's
// public key matches the expected identity.
func TestPrivateKey_Identity(t *testing.T) {
	t.Parallel()

	for _, test := range privateKeyIdentityTests {
		b, err := os.ReadFile(test.Filename)
		if err != nil {
			t.Fatal(err)
		}

		block, _ := pem.Decode(bytes.TrimSpace(b))
		if block.Type != "PRIVATE KEY" {
			t.Fatalf("failed to decode file %s as PEM private key", test.Filename)
		}
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse private key %s: %v", test.Filename, err)
		}

		sshKey, err := ssh.NewPrivateKey(privKey)
		if err != nil {
			t.Fatalf("failed to create SSH private key for %s: %v", test.Filename, err)
		}
		computedID, err := ssh.PublicKeyIdentity(sshKey.Public())
		if err != nil {
			t.Fatalf("failed to compute identity for %s: %v", test.Filename, err)
		}
		if computedID != test.Identity {
			t.Fatalf("identity mismatch for %s: got %s want %s", test.Filename, computedID, test.Identity)
		}
	}
}

var privateKeyIdentityTests = []struct {
	Filename string
	Identity ssh.Identity
}{
	{
		Filename: "testdata/keys/ed25519",
		Identity: parseIdentity("SHA256:rGc55XPHw1pCcd1hg0K2U4sgFeY6i5X88wkEOpmtSkw"),
	},
	{
		Filename: "testdata/keys/rsa",
		Identity: parseIdentity("SHA256:sPCOWZS69LBT9srkX7/EeQNYBXhBOEc+s27LSVkMPa4"),
	},
	{
		Filename: "testdata/keys/p256",
		Identity: parseIdentity("SHA256:SW4VaLkr1qifW7BMdKOK+3RcxOFdleT2bdFKnrLjZEk"),
	},
	{
		Filename: "testdata/keys/p384",
		Identity: parseIdentity("SHA256:MohftOAmTXO2J98bn0oITrH9h57g4W7UfrmRaM9qNy4"),
	},
	{
		Filename: "testdata/keys/p521",
		Identity: parseIdentity("SHA256:ZRnbh8jBYMDL8yb+GYx1iFdaDfNR6lIrS4KX60hyFbA"),
	},
}

func parseIdentity(s string) ssh.Identity {
	id, _ := ssh.ParseIdentity(s)
	return id
}

// TestParsePublicKey parses each SSH public key in authorized_keys format
// from testdata and verifies that its identity computed via
// [ssh.PublicKeyIdentity] matches the expected SHA256 fingerprint.
func TestParsePublicKey(t *testing.T) {
	t.Parallel()

	for _, test := range publicKeyIdentityTests {
		data, err := os.ReadFile(test.Filename)
		if err != nil {
			t.Fatal(err)
		}

		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			t.Fatalf("malformed authorized_keys entry in %s", test.Filename)
		}
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			t.Fatalf("failed to base64-decode key blob in %s: %v", test.Filename, err)
		}

		pub, err := parseSSHPublicKey(blob)
		if err != nil {
			t.Fatalf("failed to parse public key %s: %v", test.Filename, err)
		}
		id, err := ssh.PublicKeyIdentity(pub)
		if err != nil {
			t.Fatalf("failed to compute identity for %s: %v", test.Filename, err)
		}
		if id != test.Identity {
			t.Fatalf("identity mismatch for %s: got %s want %s", test.Filename, id, test.Identity)
		}
	}
}

var publicKeyIdentityTests = []struct {
	Filename string
	Identity ssh.Identity
}{
	{
		Filename: "testdata/keys/ed25519.pub",
		Identity: parseIdentity("SHA256:rGc55XPHw1pCcd1hg0K2U4sgFeY6i5X88wkEOpmtSkw"),
	},
	{
		Filename: "testdata/keys/rsa.pub",
		Identity: parseIdentity("SHA256:sPCOWZS69LBT9srkX7/EeQNYBXhBOEc+s27LSVkMPa4"),
	},
	{
		Filename: "testdata/keys/p256.pub",
		Identity: parseIdentity("SHA256:SW4VaLkr1qifW7BMdKOK+3RcxOFdleT2bdFKnrLjZEk"),
	},
	{
		Filename: "testdata/keys/p384.pub",
		Identity: parseIdentity("SHA256:MohftOAmTXO2J98bn0oITrH9h57g4W7UfrmRaM9qNy4"),
	},
	{
		Filename: "testdata/keys/p521.pub",
		Identity: parseIdentity("SHA256:ZRnbh8jBYMDL8yb+GYx1iFdaDfNR6lIrS4KX60hyFbA"),
	},
}

// parseSSHPublicKey decodes an SSH RFC 4253 / 5656 wire-format public-key blob.
func parseSSHPublicKey(blob []byte) (crypto.PublicKey, error) {
	r := bytes.NewReader(blob)
	readString := func() ([]byte, error) {
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	algorithm, err := readString()
	if err != nil {
		return nil, err
	}
	switch string(algorithm) {
	case "ssh-ed25519":
		key, err := readString()
		if err != nil {
			return nil, err
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key size %d", len(key))
		}
		return ed25519.PublicKey(key), nil

	case "ssh-rsa":
		eBytes, err := readString()
		if err != nil {
			return nil, err
		}
		nBytes, err := readString()
		if err != nil {
			return nil, err
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() {
			return nil, fmt.Errorf("rsa public exponent too large")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil

	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		curveName, err := readString()
		if err != nil {
			return nil, err
		}
		point, err := readString()
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch string(curveName) {
		case "nistp256":
			curve = elliptic.P256()
		case "nistp384":
			curve = elliptic.P384()
		case "nistp521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unknown ECDSA curve %s", curveName)
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(point) != 1+2*size || point[0] != 0x04 {
			return nil, fmt.Errorf("invalid ECDSA point")
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(point[1 : 1+size]),
			Y:     new(big.Int).SetBytes(point[1+size:]),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm %s", algorithm)
	}
}
