// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// ParseIdentity parses s and returns it as Identity.
// It supports SSH fingerprint format: SHA256:base64.
//
// If s is the empty string, it returns the Identity zero
// value - for which IsZero returns true - and no error.
func ParseIdentity(s string) (Identity, error) {
	if s == "" {
		return Identity{}, nil
	}

	var i Identity
	if err := i.UnmarshalText([]byte(strings.TrimRight(s, "="))); err != nil {
		return Identity{}, err
	}
	return i, nil
}

// Identity represents a SSH public key fingerprint.
// The zero value of Identity is a valid, empty identity.
type Identity struct {
	hash [32]byte
}

var zeroIdentity = Identity{}

// IsZero returns true if i is the Identity zero value.
func (i Identity) IsZero() bool { return i == zeroIdentity }

// MarshalText returns a textual representation of the identity in OpenSSH format.
func (i Identity) MarshalText() ([]byte, error) {
	var buf [50]byte
	b := append(buf[:0], "SHA256:"...)
	return base64.RawStdEncoding.AppendEncode(b, i.hash[:]), nil
}

// UnmarshalText parses the textual representation of an identity in OpenSSH format.
func (i *Identity) UnmarshalText(text []byte) error {
	if !bytes.HasPrefix(text, []byte("SHA256:")) {
		return errors.New("ssh: invalid identity")
	}
	text = text[7:]

	var dec [32]byte
	if n := base64.RawStdEncoding.DecodedLen(len(text)); n != len(dec) {
		return errors.New("ssh: invalid identity length " + strconv.Itoa(n))
	}
	n, err := base64.RawStdEncoding.Decode(dec[:], text)
	if err != nil {
		return err
	}
	if n != len(dec) {
		return errors.New("ssh: invalid identity length " + strconv.Itoa(n))
	}

	i.hash = dec
	return nil
}

// String returns the OpenSSH format string representation of the identity.
// Returns an empty string for the zero value.
func (i Identity) String() string {
	if i.IsZero() {
		return ""
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(i.hash[:])
}

// IdentityError is returned when a peer's identity does not match the expected identity.
type IdentityError struct {
	PeerIdentity Identity // Identity received from the connection peer
	Identity     Identity // Expected peer identity
}

func (e IdentityError) Error() string {
	var empty Identity
	if e.PeerIdentity == empty {
		return "ssh: no certificate provided by peer"
	}
	if e.Identity == empty {
		return "ssh: peer identity " + e.PeerIdentity.String() + " doesn't match"
	}
	return "ssh: peer identity " + e.PeerIdentity.String() + " doesn't match " + e.Identity.String()
}

// PeerIdentity extracts and returns the Identity of the peer's public key from a TLS connection state.
// It returns an error if the peer did not provide a certificate during the TLS handshake.
//
// A TLS client should always receive a certificate containing the server's public key.
// A TLS server has to request a certificate, and the client might not have one or may choose not to send it.
func PeerIdentity(state *tls.ConnectionState) (Identity, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return Identity{}, IdentityError{}
	}
	return CertificateIdentity(state.PeerCertificates[0])
}

// CertificateIdentity returns the identity of the certificate's
// public key.
func CertificateIdentity(cert *x509.Certificate) (Identity, error) {
	return PublicKeyIdentity(cert.PublicKey)
}

// PublicKeyIdentity computes and returns the Identity of the given public key.
// It supports Ed25519, ECDSA (P256, P384, P521), and RSA keys.
// It returns an error for unsupported key types.
func PublicKeyIdentity(key crypto.PublicKey) (Identity, error) {
	switch key := key.(type) {
	case ed25519.PublicKey:
		return ed25519Identity(key), nil
	case *ecdsa.PublicKey:
		return ecdsaIdentity(key), nil
	case *rsa.PublicKey:
		return rsaIdentity(key), nil
	default:
		return Identity{}, fmt.Errorf("ssh: unsupported public key type: %T", key)
	}
}

// ed25519Identity computes the SHA256 identity of an Ed25519 public key.
func ed25519Identity(key ed25519.PublicKey) Identity {
	var buf [4 + 11 + 4 + ed25519.PublicKeySize]byte
	b := buf[:0]

	b = binary.BigEndian.AppendUint32(b, uint32(len(KeyTypeEd25519))) // #nosec G115
	b = append(b, KeyTypeEd25519...)

	b = binary.BigEndian.AppendUint32(b, uint32(len(key))) // #nosec G115
	b = append(b, key...)

	return Identity{hash: sha256.Sum256(b)}
}

// rsaIdentity computes the SHA256 identity of an RSA public key.
func rsaIdentity(key *rsa.PublicKey) Identity {
	if key.E < 0 {
		return Identity{}
	}
	// RFC 4253, Section 6.6 encodes e and n as mpint per RFC 4251, Section 5:
	// if the MSB of the magnitude is set, a 0x00 byte must be prepended so the
	// value is interpreted as positive. RSA moduli always have the MSB set.
	exp := binary.BigEndian.AppendUint64(make([]byte, 0, 8), uint64(key.E)) // #nosec G115
	exp = exp[bits.LeadingZeros64(uint64(key.E))/8:]                       // #nosec G115
	if len(exp) > 0 && exp[0]&0x80 != 0 {
		exp = append([]byte{0x00}, exp...)
	}

	nBytes := key.N.Bytes()
	if len(nBytes) > 0 && nBytes[0]&0x80 != 0 {
		nBytes = append([]byte{0x00}, nBytes...)
	}

	size := 4 + len(KeyTypeRSA) + 4 + len(exp) + 4 + len(nBytes)
	b := make([]byte, 0, size)

	b = binary.BigEndian.AppendUint32(b, uint32(len(KeyTypeRSA))) // #nosec G115
	b = append(b, KeyTypeRSA...)

	b = binary.BigEndian.AppendUint32(b, uint32(len(exp))) // #nosec G115
	b = append(b, exp...)

	b = binary.BigEndian.AppendUint32(b, uint32(len(nBytes))) // #nosec G115
	b = append(b, nBytes...)

	return Identity{hash: sha256.Sum256(b)}
}

// ecdsaIdentity computes the SHA256 identity of an ECDSA (P256, P384 or P521) public key.
func ecdsaIdentity(key *ecdsa.PublicKey) Identity {
	var (
		keyType   string
		curveName string
	)

	switch key.Curve {
	case elliptic.P256():
		keyType = KeyTypeP256
		curveName = "nistp256"
	case elliptic.P384():
		keyType = KeyTypeP384
		curveName = "nistp384"
	case elliptic.P521():
		keyType = KeyTypeP521
		curveName = "nistp521"
	default:
		return Identity{}
	}

	pointBytes, err := key.Bytes()
	if err != nil {
		return Identity{}
	}

	// RFC 5656, Section 3.1 encodes Q as the SEC 1 uncompressed point
	// 0x04 || X || Y, including the 0x04 prefix.
	size := 4 + len(keyType) + 4 + len(curveName) + 4 + len(pointBytes)
	b := make([]byte, 0, size)

	b = binary.BigEndian.AppendUint32(b, uint32(len(keyType))) // #nosec G115
	b = append(b, keyType...)

	b = binary.BigEndian.AppendUint32(b, uint32(len(curveName))) // #nosec G115
	b = append(b, curveName...)

	b = binary.BigEndian.AppendUint32(b, uint32(len(pointBytes))) // #nosec G115
	b = append(b, pointBytes...)

	return Identity{hash: sha256.Sum256(b)}
}
