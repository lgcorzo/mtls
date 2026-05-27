// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
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
		Identity: parseIdentity("SHA256:gqFD/f5dw7/oG7rBDdoyOA3pVpfReq61L6tIyJ/4deU"),
	},
	{
		Filename: "testdata/keys/rsa",
		Identity: parseIdentity("SHA256:AzWFDZ4Pdz2ckSjPVl0tVff1+/EuAbaOfn5hGyKEXMQ"),
	},
	{
		Filename: "testdata/keys/p256",
		Identity: parseIdentity("SHA256:nHy3X3UYvk0z7oaB60XJWCA4qumpEIc9iNBaHrqi8qE"),
	},
	{
		Filename: "testdata/keys/p384",
		Identity: parseIdentity("SHA256:9dv2M6NArMjm5M4lnynxXMuaMXDLfCRO7NRxT3Hg+yE"),
	},
	{
		Filename: "testdata/keys/p521",
		Identity: parseIdentity("SHA256:0lDPq95asBfIFw/X9a2oD/0edy8kEw7YS03EDJePIyw"),
	},
}

func parseIdentity(s string) ssh.Identity {
	id, _ := ssh.ParseIdentity(s)
	return id
}
