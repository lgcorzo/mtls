// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"slices"
)

// Signer extends [crypto.Signer] with an [Identity] method
// to identify the signing key.
//
// Signer is useful for private keys that are not directly accessible.
// For example, keys in hardware modules.
type Signer interface {
	crypto.Signer

	// Identity returns a stable identifier for the Signer's public key.
	Identity() Identity
}

// GenerateKey generates a new [PrivateKey].
//
// Currently, it returns an Ed25519 private key. However,
// this might change and callers must not rely on the concrete
// key type.
func GenerateKey() (*PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(priv)
}

// NewPrivateKey returns a new [PrivateKey] wrapping the given private key.
//
// Currently supported types are [ed25519.PrivateKey], [*ecdsa.PrivateKey]
// and [*rsa.PrivateKey].
func NewPrivateKey(priv crypto.PrivateKey) (*PrivateKey, error) {
	var (
		signer   crypto.Signer
		identity Identity
	)

	switch priv := priv.(type) {
	case ed25519.PrivateKey:
		pub := append(make(ed25519.PublicKey, 0, ed25519.PublicKeySize), priv[32:]...)
		identity = ed25519Identity(pub)
		signer = priv

	case *ecdsa.PrivateKey:
		identity = ecdsaIdentity(&priv.PublicKey)
		signer = priv

	case *rsa.PrivateKey:
		identity = rsaIdentity(&priv.PublicKey)
		priv.Precompute()
		signer = priv

	default:
		return nil, fmt.Errorf("ssh: unsupported private key type: %T", priv)
	}

	return &PrivateKey{
		signer:   signer,
		identity: identity,
	}, nil
}

// PrivateKey is a [Signer] with a directly accessible private key.
type PrivateKey struct {
	signer   crypto.Signer
	identity Identity
}

// Private returns the underlying private key. Either a [ed25519.PrivateKey],
// [*ecdsa.PrivateKey] or [*rsa.PrivateKey].
func (pk *PrivateKey) Private() crypto.PrivateKey { return pk.signer }

// Public returns the public key corresponding to the private key.
func (pk *PrivateKey) Public() crypto.PublicKey { return pk.signer.Public() }

// Identity returns the identity of the private key's public key.
func (pk *PrivateKey) Identity() Identity { return pk.identity }

// Sign signs message with the private key. See [crypto.Signer] for
// algorithm-specific requirements on message and opts.
func (pk *PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return pk.signer.Sign(random, message, opts)
}

// parsePublicKey parses the key blob and returns the public key.
func parsePublicKey(blob []byte) (crypto.PublicKey, error) {
	r := &reader{data: blob}
	algorithm, err := r.readString()
	if err != nil {
		return nil, err
	}

	switch algorithm {
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %s", algorithm)

	case KeyTypeEd25519:
		keyBytes, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ssh: invalid ed25519 key size")
		}
		return ed25519.PublicKey(slices.Clone(keyBytes)), nil

	case KeyTypeRSA, KeyTypeRSA + "-sha256":
		eBytes, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		nBytes, err := r.readBytes()
		if err != nil {
			return nil, err
		}

		e := new(big.Int).SetBytes(eBytes)
		n := new(big.Int).SetBytes(nBytes)
		if !e.IsInt64() {
			return nil, fmt.Errorf("ssh: RSA exponent too large")
		}
		return &rsa.PublicKey{E: int(e.Int64()), N: n}, nil

	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		curveName, err := r.readString()
		if err != nil {
			return nil, err
		}
		pointBytes, err := r.readBytes()
		if err != nil {
			return nil, err
		}

		var curve elliptic.Curve
		switch curveName {
		case "nistp256":
			curve = elliptic.P256()
		case "nistp384":
			curve = elliptic.P384()
		case "nistp521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("ssh: unknown ECDSA curve %s", curveName)
		}

		if len(pointBytes) != 2*curve.Params().BitSize/8+1 || pointBytes[0] != 0x04 {
			return nil, fmt.Errorf("ssh: invalid ECDSA point")
		}
		keySize := curve.Params().BitSize / 8
		x := new(big.Int).SetBytes(pointBytes[1 : 1+keySize])
		y := new(big.Int).SetBytes(pointBytes[1+keySize:])
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}
}
