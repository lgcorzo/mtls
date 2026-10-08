// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package mtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"time"
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

// ParsePrivateKey parses s and returns it as [PrivateKey].
func ParsePrivateKey(s string) (*PrivateKey, error) {
	var pk PrivateKey
	if err := pk.UnmarshalText([]byte(s)); err != nil {
		return nil, err
	}
	return &pk, nil
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
		err      error
	)

	switch priv := priv.(type) {
	case ed25519.PrivateKey:
		pub := append(make(ed25519.PublicKey, 0, ed25519.PublicKeySize), priv[32:]...)
		if identity, err = ed25519Identity(pub); err != nil {
			return nil, err
		}
		signer = priv

	case *ecdsa.PrivateKey:
		if identity, err = ecdsaIdentity(priv); err != nil {
			return nil, err
		}
		signer = priv

	case *rsa.PrivateKey:
		if uint64(priv.E) > math.MaxUint32 {
			return nil, errors.New("mtls: public RSA exponent " + strconv.Itoa(priv.E) + " is too large")
		}
		if identity, err = rsaIdentity(priv); err != nil {
			return nil, err
		}
		priv.Precompute()
		signer = priv

	default:
		return nil, fmt.Errorf("mtls: unsupported private key type: %T", priv)
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

// MarshalText returns the key's textual representation.
func (pk *PrivateKey) MarshalText() ([]byte, error) {
	switch priv := pk.signer.(type) {
	case ed25519.PrivateKey:
		var text [46]byte
		b := append(text[:0], "k1:"...)
		b = base64.RawURLEncoding.AppendEncode(b, priv[:ed25519.SeedSize])
		return b, nil

	case *ecdsa.PrivateKey:
		// FillBytes returns a fixed-width slice so all private key
		// representations of a given curve are the same length. A
		// P-521 private key is at most 66 bytes long.
		var p [66]byte
		d := priv.D.FillBytes(p[:])
		d = d[66-(priv.Curve.Params().BitSize+7)/8:]

		var buf [3 + 88]byte
		b := append(buf[:0], "k2:"...)
		b = base64.RawURLEncoding.AppendEncode(b, d)
		return b, nil

	case *rsa.PrivateKey:
		return base64.RawURLEncoding.AppendEncode([]byte("k3:"), encodeRSAPrivateKey(priv)), nil

	default:
		return nil, fmt.Errorf("mtls: unsupported private key type: %T", priv)
	}
}

// UnmarshalText parses a private key's textual representation. See
// [PrivateKey.MarshalText] for the accepted formats.
func (pk *PrivateKey) UnmarshalText(text []byte) error {
	switch {
	case bytes.HasPrefix(text, []byte("k1:")):
		return pk.unmarshalEdDSA(text[3:])
	case bytes.HasPrefix(text, []byte("k2:")):
		return pk.unmarshalECDSA(text[3:])
	case bytes.HasPrefix(text, []byte("k3:")):
		return pk.unmarshalRSA(text[3:])
	default:
		return errors.New("mtls: invalid private key")
	}
}

// String returns the key's string representation.
//
// Its output is equivalent to [PrivateKey.MarshalText].
func (pk *PrivateKey) String() string {
	b, err := pk.MarshalText()
	if err != nil {
		return ""
	}
	return string(b)
}

func (pk *PrivateKey) unmarshalEdDSA(text []byte) error {
	var dec [32]byte
	if n := base64.RawURLEncoding.DecodedLen(len(text)); n != len(dec) {
		return errors.New("mtls: invalid EdDSA private key length " + strconv.Itoa(n))
	}
	n, err := base64.RawURLEncoding.Decode(dec[:], text)
	if err != nil {
		return err
	}
	if n != len(dec) {
		return errors.New("mtls: invalid EdDSA private key length " + strconv.Itoa(n))
	}

	priv := ed25519.NewKeyFromSeed(dec[:])
	identity, err := ed25519Identity(ed25519.PublicKey(priv[ed25519.SeedSize:]))
	if err != nil {
		return err
	}
	pk.signer, pk.identity = priv, identity
	return nil
}

func (pk *PrivateKey) unmarshalECDSA(text []byte) error {
	var (
		curve elliptic.Curve
		n     = base64.RawURLEncoding.DecodedLen(len(text))
	)
	switch n {
	default:
		return errors.New("mtls: invalid ECDSA private key length " + strconv.Itoa(n))
	case 32:
		curve = elliptic.P256()
	case 48:
		curve = elliptic.P384()
	case 66:
		curve = elliptic.P521()
	}

	buf := make([]byte, 0, n)
	buf, err := base64.RawURLEncoding.AppendDecode(buf, text)
	if err != nil {
		return fmt.Errorf("mtls: invalid ECDSA private key: %w", err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(curve, buf)
	if err != nil {
		return fmt.Errorf("mtls: invalid ECDSA private key: %w", err)
	}
	identity, err := ecdsaIdentity(priv)
	if err != nil {
		return err
	}

	pk.signer, pk.identity = priv, identity
	return nil
}

func (pk *PrivateKey) unmarshalRSA(text []byte) error {
	var err error
	data := make([]byte, 0, base64.RawURLEncoding.DecodedLen(len(text)))
	if data, err = base64.RawURLEncoding.AppendDecode(data, text); err != nil {
		return err
	}

	var E uint32
	if len(data) < 6 {
		return errors.New("mtls: invalid RSA private key parameter E")
	}
	if n := binary.BigEndian.Uint16(data); n != 4 {
		return errors.New("mtls: invalid RSA private key parameter E: invalid encoding length " + strconv.Itoa(int(n)))
	}
	E = binary.BigEndian.Uint32(data[2:])
	data = data[6:]

	var P, Q, D *big.Int
	if data, P, err = decodeRSAParam(data); err != nil {
		return fmt.Errorf("mtls: invalid RSA private key parameter P: %w", err)
	}
	if data, Q, err = decodeRSAParam(data); err != nil {
		return fmt.Errorf("mtls: invalid RSA private key parameter Q: %w", err)
	}
	if data, D, err = decodeRSAParam(data); err != nil {
		return fmt.Errorf("mtls: invalid RSA private key parameter D: %w", err)
	}
	if len(data) != 0 {
		return errors.New("mtls: invalid RSA private key: private key contains additional data")
	}

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).Mul(P, Q),
			E: int(E),
		},
		D:      D,
		Primes: []*big.Int{P, Q},
	}
	priv.Precompute()
	if err = priv.Validate(); err != nil {
		return fmt.Errorf("mtls: invalid RSA private key: %w", err)
	}

	identity, err := rsaIdentity(priv)
	if err != nil {
		return err
	}

	pk.signer, pk.identity = priv, identity
	return nil
}

// encodeRSAPrivateKey returns the RSA key's binary representation:
//
//	len(E) | E | len(P) | P | len(Q) | Q | len(D) | D
//
// All numbers are represented in big endian.
//
// Values that can be re-computed are omitted to be space efficient.
// For example, the modulus N = PQ. The private exponent D can also
// be re-computed given P and Q as D = E⁻¹ mod φ(N) where φ(N) = (p-1)(q-1).
//
// However, FIPS 186-5 requires computing it as E⁻¹ mod λ(N) where λ(N) = lcm(p-1, q-1).
// Hence, we include D to avoid re-implementing private exponent calculations.
// The binary representation puts D at the end such that we can support shorter
// private keys (without D) in the future.
func encodeRSAPrivateKey(priv *rsa.PrivateKey) []byte {
	var (
		D, P, Q = priv.D, priv.Primes[0], priv.Primes[1]
		d, p, q = (D.BitLen() + 7) / 8, (P.BitLen() + 7) / 8, (Q.BitLen() + 7) / 8

		buf = make([]byte, max(d, p, q))
		out = make([]byte, 0, 12+d+p+q) // length-prefixed encoded len: 2 + 4 + 2 + d + 2 + p + 2 + q
	)

	out = binary.BigEndian.AppendUint16(out, 4)
	out = binary.BigEndian.AppendUint32(out, uint32(priv.E))

	out = binary.BigEndian.AppendUint16(out, uint16(p))
	out = append(out, P.FillBytes(buf[:p])...)

	out = binary.BigEndian.AppendUint16(out, uint16(q))
	out = append(out, Q.FillBytes(buf[:q])...)

	out = binary.BigEndian.AppendUint16(out, uint16(d))
	out = append(out, D.FillBytes(buf[:d])...)
	return out
}

var (
	oidPublicKeyEdDSA = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func ed25519Identity(pub ed25519.PublicKey) (Identity, error) {
	b, err := asn1.Marshal(publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEdDSA,
		},
		PublicKey: asn1.BitString{BitLength: len(pub) * 8, Bytes: pub},
	})
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		hash: sha256.Sum256(b),
	}, nil
}

func ecdsaIdentity(key *ecdsa.PrivateKey) (Identity, error) {
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		// We generate the private/public key pair. Hence, (X,Y)
		// should always be a point on the elliptic curve.
		// However, we want to be really sure to not accidentally
		// compute an invalid identity.
		return Identity{}, errors.New("mtls: invalid ECDSA public key for curve")
	}

	var curveID asn1.ObjectIdentifier
	switch key.Curve {
	default:
		return Identity{}, errors.New("mtls: curve " + key.Curve.Params().Name + " is not supported")
	case elliptic.P256():
		curveID = oidNamedCurveP256
	case elliptic.P384():
		curveID = oidNamedCurveP384
	case elliptic.P521():
		curveID = oidNamedCurveP521
	}
	params, err := asn1.Marshal(curveID)
	if err != nil {
		return Identity{}, err
	}

	pubKey := elliptic.Marshal(key.Curve, key.X, key.Y) //nolint:staticcheck // keep backwards compatibility for ASN.1 EC point encoding
	b, err := asn1.Marshal(publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyECDSA,
			Parameters: asn1.RawValue{FullBytes: params},
		},
		PublicKey: asn1.BitString{BitLength: len(pubKey) * 8, Bytes: pubKey},
	})
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		hash: sha256.Sum256(b),
	}, nil
}

func rsaIdentity(key *rsa.PrivateKey) (Identity, error) {
	type PKCS1 struct {
		N *big.Int
		E int
	}
	pubKey, err := asn1.Marshal(PKCS1{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return Identity{}, fmt.Errorf("mtls: failed to encode RSA public key: %w", err)
	}
	b, err := asn1.Marshal(publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		},
		PublicKey: asn1.BitString{BitLength: len(pubKey) * 8, Bytes: pubKey},
	})
	if err != nil {
		return Identity{}, fmt.Errorf("mtls: failed to encode RSA public key: %w", err)
	}

	return Identity{
		hash: sha256.Sum256(b),
	}, nil
}

// decodeRSAParam decodes a length-encoded big endian binary
// representation of an RSA private key parameter. In particular,
// the private exponent D and the prime factors P and Q.
func decodeRSAParam(b []byte) ([]byte, *big.Int, error) {
	if len(b) < 2 {
		return nil, nil, errors.New("invalid length encoding")
	}

	n := binary.BigEndian.Uint16(b)
	if n == 0 {
		return nil, nil, errors.New("parameter length is zero")
	}
	if int(n) > len(b)-2 {
		return nil, nil, errors.New("parameter length " + strconv.Itoa(int(n)) + " exceeds data")
	}
	return b[2+n:], new(big.Int).SetBytes(b[2 : 2+n]), nil
}

// newCertificate returns a new TLS certificate using the given signer.
func newCertificate(signer Signer) (*tls.Certificate, error) {
	now := time.Now().UTC()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: signer.Identity().String(),
		},
		NotBefore: now,
		NotAfter:  now.Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}
