// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
)

// ErrKeyNotFound is returned when no Ed25519 key matching the requested
// identity or comment is held by the SSH agent.
var ErrKeyNotFound = errors.New("ssh: key not found in agent")

// SSH public key types as specified by RFC 4253 (RSA), RFC 5656 (ECDSA)
// and RFC 8709 (Ed25519).
const (
	KeyTypeEd25519 = "ssh-ed25519"
	KeyTypeP256    = "ecdsa-sha2-nistp256"
	KeyTypeP384    = "ecdsa-sha2-nistp384"
	KeyTypeP521    = "ecdsa-sha2-nistp521"
	KeyTypeRSA     = "ssh-rsa"
)

// SSH agent protocol message types.
const (
	sshAgentFailure            = 5
	sshAgentcRequestIdentities = 11
	sshAgentIdentitiesAnswer   = 12
	sshAgentcSignRequest       = 13
	sshAgentSignResponse       = 14
)

const maxAgentMessageSize = 256 * 1024

// AgentError is returned when the SSH agent replies with a protocol-level
// failure (SSH_AGENT_FAILURE etc.). Distinct from transport errors so
// callers can tell "agent refused" (e.g. user declined touch) from
// "socket broken".
type AgentError struct {
	msgType byte // TODO: don't expose this. Also, use a string and convert msg type to human-readable messages
}

func (e AgentError) Error() string {
	return fmt.Sprintf("ssh: agent error (msg type %d)", e.msgType)
}

// UnsupportedPublicKey is the placeholder [crypto.PublicKey] returned by
// [AgentKey.Public] when the agent holds a key whose public key blob cannot
// be parsed into a supported key type (see the KeyType constants).
//
// It carries the underlying parse error, which is accessible via Error or
// Unwrap, so callers can inspect why the key is unsupported.
type UnsupportedPublicKey struct {
	err error
}

// String returns the underlying parse error message.
func (e UnsupportedPublicKey) String() string { return e.err.Error() }

// Error returns the underlying parse error message.
func (e UnsupportedPublicKey) Error() string { return e.err.Error() }

// Unwrap returns the underlying parse error.
func (e UnsupportedPublicKey) Unwrap() error { return e.err }

// Equal reports whether o is an UnsupportedPublicKey carrying an equal
// error message.
func (e UnsupportedPublicKey) Equal(o crypto.PublicKey) bool {
	if v, ok := o.(UnsupportedPublicKey); ok {
		return e.Error() == v.Error()
	}
	return false
}

// DialAgent connects to the SSH agent listening on $SSH_AUTH_SOCK.
// The Agent owns the connection — call Close to release it. Returns
// an error if SSH_AUTH_SOCK is empty or the socket cannot be dialed.
//
// On Windows, DialAgent currently returns an error; use NewAgent with a
// named-pipe conn.
func DialAgent() (*Agent, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("ssh: agent support is not implemented on Windows; use NewAgent with a named-pipe conn")
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, errors.New("ssh: SSH_AUTH_SOCK not set")
	}
	conn, err := net.Dial("unix", socket) // #nosec G704
	if err != nil {
		return nil, err
	}
	return NewAgent(conn), nil
}

// NewAgent returns an Agent that communicates with an SSH agent over conn.
// The Agent takes ownership of conn: Close will close conn.
func NewAgent(conn net.Conn) *Agent {
	return &Agent{
		conn: conn,
	}
}

// Agent is a client of an SSH authentication agent. Method calls are
// serialized internally and safe for concurrent use from multiple goroutines.
type Agent struct {
	mu   sync.Mutex
	conn net.Conn
}

// Keys returns all keys held by the agent.
//
// The private key bytes remain within the agent and signing operations
// are executed by the Agent. Agent-managed RSA and ECDSA keys cannot be
// used to sign TLS handshakes. Refer to [AgentKey] documentation.
func (a *Agent) Keys() ([]*AgentKey, error) {
	respType, respPayload, err := a.sendRequest(sshAgentcRequestIdentities, nil)
	if err != nil {
		return nil, err
	}
	if respType != sshAgentIdentitiesAnswer {
		return nil, &AgentError{msgType: respType}
	}

	r := &reader{data: respPayload}
	nkeys, err := r.readUint32()
	if err != nil {
		return nil, err
	}

	var keys []*AgentKey
	for range nkeys {
		keyBlob, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		keyComment, err := r.readString()
		if err != nil {
			return nil, err
		}
		algorithm, err := (&reader{data: keyBlob}).readString()
		if err != nil {
			return nil, err
		}

		keys = append(keys, &AgentKey{
			agent:     a,
			blob:      keyBlob,
			pubKey:    nil, // Initialized lazily
			identity:  Identity{hash: sha256.Sum256(keyBlob)},
			algorithm: algorithm,
			comment:   keyComment,
		})
	}
	return keys, nil
}

// KeyByID returns the first [AgentKey] whose identity matches the given
// identity, or ErrKeyNotFound. This is optimized to only parse the matching key.
func (a *Agent) KeyByID(id Identity) (*AgentKey, error) {
	respType, respPayload, err := a.sendRequest(sshAgentcRequestIdentities, nil)
	if err != nil {
		return nil, err
	}

	if respType != sshAgentIdentitiesAnswer {
		return nil, AgentError{msgType: respType}
	}

	r := &reader{data: respPayload}
	nkeys, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	for range nkeys {
		keyBlob, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		// The comment follows every key blob and must be consumed on each
		// iteration to keep the reader aligned, even when the key does not match.
		keyComment, err := r.readString()
		if err != nil {
			return nil, err
		}

		v := Identity{hash: sha256.Sum256(keyBlob)}
		if id == v {
			algorithm, err := (&reader{data: keyBlob}).readString()
			if err != nil {
				return nil, err
			}
			return &AgentKey{
				agent:     a,
				blob:      keyBlob,
				pubKey:    nil, // Initialized lazily
				identity:  id,
				algorithm: algorithm,
				comment:   keyComment,
			}, nil
		}
	}
	return nil, ErrKeyNotFound
}

// KeyByComment returns the first [AgentKey] whose comment matches the given
// comment, or ErrKeyNotFound. This is optimized to only parse the matching key.
func (a *Agent) KeyByComment(comment string) (*AgentKey, error) {
	respType, respPayload, err := a.sendRequest(sshAgentcRequestIdentities, nil)
	if err != nil {
		return nil, err
	}

	if respType != sshAgentIdentitiesAnswer {
		return nil, AgentError{msgType: respType}
	}

	r := &reader{data: respPayload}
	nKeys, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	for range nKeys {
		keyBlob, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		keyComment, err := r.readString()
		if err != nil {
			return nil, err
		}
		if keyComment == comment {
			algorithm, err := (&reader{data: keyBlob}).readString()
			if err != nil {
				return nil, err
			}
			return &AgentKey{
				agent:     a,
				blob:      keyBlob,
				pubKey:    nil, // Initialized lazily
				identity:  Identity{hash: sha256.Sum256(keyBlob)},
				algorithm: algorithm,
				comment:   keyComment,
			}, nil
		}
	}
	return nil, ErrKeyNotFound
}

// Close closes the underlying connection.
func (a *Agent) Close() error { return a.conn.Close() }

// sendRequest frames, writes a request, and reads one response.
//
// The write and the matching read form a single transaction on the shared
// connection and must not interleave with other requests, so sendRequest
// holds a.mu for the round-trip only. Callers parse the returned payload
// without the lock.
func (a *Agent) sendRequest(msgType byte, payload []byte) (byte, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(payload) > maxAgentMessageSize {
		return 0, nil, fmt.Errorf("ssh: payload size %d exceeds maximum %d", len(payload), maxAgentMessageSize)
	}

	// Write the complete message: uint32 length || msg_type || payload
	frame := make([]byte, 0, 4+1+len(payload))
	frame = binary.BigEndian.AppendUint32(frame, 1+uint32(len(payload))) // #nosec G115
	frame = append(frame, msgType)
	frame = append(frame, payload...)
	if _, err := a.conn.Write(frame); err != nil {
		return 0, nil, err
	}

	// Read the response: uint32 length || byte msg_type || payload
	var lenFrameResp [4]byte
	if _, err := io.ReadFull(a.conn, lenFrameResp[:]); err != nil {
		return 0, nil, err
	}

	respLen := binary.BigEndian.Uint32(lenFrameResp[:])
	if respLen > maxAgentMessageSize {
		return 0, nil, fmt.Errorf("ssh: agent message size %d exceeds maximum %d", respLen, maxAgentMessageSize)
	}
	if respLen < 1 {
		return 0, nil, errors.New("ssh: agent response empty")
	}

	// Read the message type and payload
	respBody := make([]byte, respLen)
	if _, err := io.ReadFull(a.conn, respBody); err != nil {
		return 0, nil, err
	}

	respMsgType := respBody[0]
	respPayload := respBody[1:]
	return respMsgType, respPayload, nil
}

// AgentKey is a key held in an SSH agent. The private key bytes never leave
// the agent; signing is delegated over the protocol.
//
// Agent-managed RSA and ECDSA (P-256, P-384 and P-521) private keys cannot
// be used to sign TLS handshake messages due to signing and signature encoding
// incompatibilities. Callers should filter out such keys using [AgentKey.Type]
// when using an Agent to sign TLS handshakes.
type AgentKey struct {
	agent *Agent

	blob      []byte // SSH wire-format public key blob
	pubKey    crypto.PublicKey
	identity  Identity
	algorithm string
	comment   string
}

// Public returns the public key corresponding to the key held by the agent.
// The concrete type is one of [ed25519.PublicKey], [*ecdsa.PublicKey] or
// [*rsa.PublicKey]. If the agent's public key blob cannot be parsed, it
// returns an [UnsupportedPublicKey] carrying the parse error.
//
// The result is computed on first use and cached for subsequent calls.
func (k *AgentKey) Public() crypto.PublicKey {
	if k.pubKey != nil {
		return k.pubKey
	}

	var err error
	if k.pubKey, err = parsePublicKey(k.blob); err != nil {
		k.pubKey = UnsupportedPublicKey{err: err}
	}
	return k.pubKey
}

// Type returns the SSH public key algorithm name of the key, e.g.
// [KeyTypeEd25519]. See the KeyType constants for the recognized values.
func (k *AgentKey) Type() string { return k.algorithm }

// Identity returns the [Identity] of the key's public key.
func (k *AgentKey) Identity() Identity { return k.identity }

// Comment returns the comment the agent associates with the key, typically
// the origin of the key such as a file path or user@host label.
func (k *AgentKey) Comment() string { return k.comment }

// Sign requests a signature over message from the agent, which performs the
// signing operation so the private key never leaves the agent. It implements
// [crypto.Signer].
//
// The agent applies its own hashing, so message is the raw data to be signed,
// not a pre-computed digest. Accordingly opts.HashFunc must be 0 for Ed25519
// and ECDSA keys. For RSA keys opts.HashFunc may be 0 (let the agent choose),
// [crypto.SHA256] or [crypto.SHA512] to select the RSA signature algorithm.
//
// Because [crypto/x509] and [crypto/tls] sign a pre-computed digest and expect
// DER-encoded signatures, only Ed25519 keys can be used to sign TLS handshake
// messages; see the [AgentKey] documentation.
func (k *AgentKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	const (
		FlagRSASHA256 = 0x02
		FlagRSASHA512 = 0x04
	)

	var flags uint32
	switch k.algorithm {
	case KeyTypeEd25519: // Ed25519 requires raw, not pre-hashed messages.
		if opts != nil && opts.HashFunc() != 0 {
			return nil, fmt.Errorf("ssh: ed25519 does not support pre-hashed input")
		}

	case KeyTypeP256, KeyTypeP384, KeyTypeP521: // ECDSA requires raw, not pre-hashed messages.
		if opts != nil && opts.HashFunc() != 0 {
			return nil, fmt.Errorf("ssh: ECDSA does not support pre-hashed input")
		}

	case KeyTypeRSA: // We don't support RSA with SHA-1. Hence, SHA-256 is the default
		flags = FlagRSASHA256
		if opts != nil && opts.HashFunc() == crypto.SHA512 {
			flags = FlagRSASHA512
		}
	}

	if len(k.blob) > maxAgentMessageSize || len(message) > maxAgentMessageSize {
		return nil, fmt.Errorf("ssh: request payload size exceeds maximum %d", maxAgentMessageSize)
	}

	// Build sign request payload (without message type).
	req := make([]byte, 0, 4+len(k.blob)+4+len(message)+4)
	req = binary.BigEndian.AppendUint32(req, uint32(len(k.blob))) // #nosec G115
	req = append(req, k.blob...)
	req = binary.BigEndian.AppendUint32(req, uint32(len(message))) // #nosec G115
	req = append(req, message...)
	req = binary.BigEndian.AppendUint32(req, flags)

	respType, respPayload, err := k.agent.sendRequest(sshAgentcSignRequest, req)
	if err != nil {
		return nil, err
	}
	if respType != sshAgentSignResponse {
		return nil, &AgentError{msgType: respType}
	}

	r := &reader{data: respPayload}
	sigBlob, err := r.readBytes()
	if err != nil {
		return nil, err
	}

	// Parse the signature blob (itself a SSH wire-format message).
	sr := &reader{data: sigBlob}
	if _, err := sr.readString(); err != nil { // extract signature algorithm
		return nil, fmt.Errorf("ssh: failed to parse signature algorithm: %w", err)
	}
	signature, err := sr.readBytes()
	if err != nil {
		return nil, fmt.Errorf("ssh: failed to parse signature: %w", err)
	}
	return signature, nil
}

// reader helps parse SSH wire-format messages.
type reader struct {
	data []byte
}

func (r *reader) readUint32() (uint32, error) {
	if len(r.data) < 4 {
		return 0, io.ErrUnexpectedEOF
	}

	v := binary.BigEndian.Uint32(r.data)
	r.data = r.data[4:]
	return v, nil
}

func (r *reader) readString() (string, error) {
	data, err := r.readBytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *reader) readBytes() ([]byte, error) {
	if len(r.data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	n := binary.BigEndian.Uint32(r.data)
	if n > maxAgentMessageSize {
		return nil, errors.New("ssh: string size " + strconv.Itoa(int(n)) + " exceeds maximum")
	}
	if int(n) > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}

	data := r.data[4 : 4+n]
	r.data = r.data[4+n:]
	return data, nil
}
