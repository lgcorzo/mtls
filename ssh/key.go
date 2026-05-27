// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
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
