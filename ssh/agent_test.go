// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lgcorzo/mtls/ssh"
)

// agentGoldenDir holds the recorded SSH agent protocol messages that the
// replay tests below use as golden values. They are captured from a live
// agent by TestRecordAgentGolden (see its documentation for how to refresh
// them).
const agentGoldenDir = "testdata/agent"

// signMessage is the fixed payload signed when recording the sign_* golden
// values. It is kept constant so a re-recorded sign request encodes to the
// exact same bytes and the replay test can assert byte-for-byte equality.
var signMessage = []byte("mtls ssh agent golden test message")

// TestAgentKeys replays the recorded SSH_AGENT_IDENTITIES_ANSWER and checks
// that Agent.Keys emits the exact SSH_AGENTC_REQUEST_IDENTITIES request and
// parses every key held by the agent at record time.
func TestAgentKeys(t *testing.T) {
	t.Parallel()

	conn := &replayConn{resp: readGolden(t, "identities_answer.bin")}
	agent := ssh.NewAgent(conn)

	keys, err := agent.Keys()
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	if got, want := conn.written.Bytes(), readGolden(t, "identities_request.bin"); !bytes.Equal(got, want) {
		t.Fatalf("request mismatch:\n got  %x\n want %x", got, want)
	}
	if len(keys) == 0 {
		t.Fatal("expected at least one key in the recorded answer")
	}

	for _, key := range keys {
		// The public key must parse (not be an UnsupportedPublicKey) and its
		// derived identity must match the identity the Agent assigned while
		// parsing the answer.
		id, err := ssh.PublicKeyIdentity(key.Public())
		if err != nil {
			t.Fatalf("failed to compute identity for %s key %q: %v", key.Type(), key.Comment(), err)
		}
		if id != key.Identity() {
			t.Fatalf("identity mismatch for %s key %q: got %s want %s", key.Type(), key.Comment(), id, key.Identity())
		}
	}
}

// TestAgentKeyByID replays the recorded answer and verifies KeyByID returns
// the key whose identity is requested, and ErrKeyNotFound otherwise.
func TestAgentKeyByID(t *testing.T) {
	t.Parallel()

	answer := readGolden(t, "identities_answer.bin")

	// Discover a real identity held by the agent from the recorded answer.
	keys, err := ssh.NewAgent(&replayConn{resp: answer}).Keys()
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	want := keys[0]

	conn := &replayConn{resp: answer}
	key, err := ssh.NewAgent(conn).KeyByID(want.Identity())
	if err != nil {
		t.Fatalf("failed to look up key by identity: %v", err)
	}
	if got := conn.written.Bytes(); !bytes.Equal(got, readGolden(t, "identities_request.bin")) {
		t.Fatalf("request mismatch:\n got  %x", got)
	}
	if key.Identity() != want.Identity() {
		t.Fatalf("identity mismatch: got %s want %s", key.Identity(), want.Identity())
	}

	// An identity the agent does not hold must not be found.
	var missing ssh.Identity
	if _, err := ssh.NewAgent(&replayConn{resp: answer}).KeyByID(missing); err != ssh.ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound for zero identity, got %v", err)
	}
}

// TestAgentKeyByComment replays the recorded answer and verifies KeyByComment
// returns the key with the requested comment, and ErrKeyNotFound otherwise.
func TestAgentKeyByComment(t *testing.T) {
	t.Parallel()

	answer := readGolden(t, "identities_answer.bin")

	keys, err := ssh.NewAgent(&replayConn{resp: answer}).Keys()
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	want := keys[0]

	conn := &replayConn{resp: answer}
	key, err := ssh.NewAgent(conn).KeyByComment(want.Comment())
	if err != nil {
		t.Fatalf("failed to look up key by comment %q: %v", want.Comment(), err)
	}
	if got := conn.written.Bytes(); !bytes.Equal(got, readGolden(t, "identities_request.bin")) {
		t.Fatalf("request mismatch:\n got  %x", got)
	}
	if key.Identity() != want.Identity() {
		t.Fatalf("identity mismatch: got %s want %s", key.Identity(), want.Identity())
	}

	if _, err := ssh.NewAgent(&replayConn{resp: answer}).KeyByComment("no-such-comment@nowhere"); err != ssh.ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound for unknown comment, got %v", err)
	}
}

// TestAgentKeySign replays, for every key type held at record time, the
// recorded SSH_AGENT_SIGN_RESPONSE. It asserts AgentKey.Sign emits the exact
// SSH_AGENTC_SIGN_REQUEST and that the recorded signature verifies against the
// key's public key.
func TestAgentKeySign(t *testing.T) {
	t.Parallel()

	answer := readGolden(t, "identities_answer.bin")

	keys, err := ssh.NewAgent(&replayConn{resp: answer}).Keys()
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	for _, key := range keys {
		t.Run(key.Type(), func(t *testing.T) {
			t.Parallel()

			signResponse := readGolden(t, "sign_response_"+key.Type()+".bin")

			// The Agent must first serve the identities answer (so Keys can
			// bind the AgentKey to this connection), then the sign response.
			conn := &replayConn{resp: append(append([]byte{}, answer...), signResponse...)}
			agent := ssh.NewAgent(conn)

			all, err := agent.Keys()
			if err != nil {
				t.Fatalf("failed to list keys: %v", err)
			}
			k := keyByType(all, key.Type())
			if k == nil {
				t.Fatalf("no %s key held by agent", key.Type())
			}

			conn.written.Reset() // discard the identities request; only inspect the sign request
			sig, err := k.Sign(nil, signMessage, nil)
			if err != nil {
				t.Fatalf("failed to sign with %s key: %v", key.Type(), err)
			}
			if got := conn.written.Bytes(); !bytes.Equal(got, readGolden(t, "sign_request_"+key.Type()+".bin")) {
				t.Fatalf("sign request mismatch:\n got  %x", got)
			}
			if err := verifySignature(k.Type(), k.Public(), signMessage, sig); err != nil {
				t.Fatalf("recorded %s signature failed to verify: %v", key.Type(), err)
			}
		})
	}
}

// keyByType returns the first key of the given SSH algorithm, or nil.
func keyByType(keys []*ssh.AgentKey, typ string) *ssh.AgentKey {
	for _, k := range keys {
		if k.Type() == typ {
			return k
		}
	}
	return nil
}

// verifySignature verifies sig (as returned by AgentKey.Sign, i.e. the inner
// signature blob with the SSH algorithm wrapper already stripped) over message
// using pub, according to the algorithm implied by typ.
func verifySignature(typ string, pub crypto.PublicKey, message, sig []byte) error {
	if _, ok := pub.(ssh.UnsupportedPublicKey); ok {
		return fmt.Errorf("public key did not parse: %v", pub)
	}

	switch typ {
	case ssh.KeyTypeEd25519:
		if !ed25519.Verify(pub.(ed25519.PublicKey), message, sig) {
			return errVerify
		}
		return nil

	case ssh.KeyTypeRSA:
		// AgentKey.Sign defaults RSA keys to rsa-sha2-256.
		h := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, h[:], sig)

	case ssh.KeyTypeP256, ssh.KeyTypeP384, ssh.KeyTypeP521:
		// The ECDSA signature blob is "mpint r || mpint s" (RFC 5656).
		r := &wireReader{data: sig}
		rb, err := r.readBytes()
		if err != nil {
			return err
		}
		sb, err := r.readBytes()
		if err != nil {
			return err
		}
		var digest []byte
		switch typ {
		case ssh.KeyTypeP256:
			d := sha256.Sum256(message)
			digest = d[:]
		case ssh.KeyTypeP384:
			d := sha512.Sum384(message)
			digest = d[:]
		default:
			d := sha512.Sum512(message)
			digest = d[:]
		}
		if !ecdsa.Verify(pub.(*ecdsa.PublicKey), digest, new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb)) {
			return errVerify
		}
		return nil

	default:
		return errVerify
	}
}

var errVerify = &verifyError{}

type verifyError struct{}

func (*verifyError) Error() string { return "signature verification failed" }

// wireReader parses length-prefixed SSH wire-format fields.
type wireReader struct {
	data []byte
}

func (r *wireReader) readBytes() ([]byte, error) {
	if len(r.data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	n := binary.BigEndian.Uint32(r.data)
	if int(n) > len(r.data)-4 {
		return nil, io.ErrUnexpectedEOF
	}
	b := r.data[4 : 4+n]
	r.data = r.data[4+n:]
	return b, nil
}

// replayConn is a net.Conn that serves pre-recorded response bytes on Read and
// captures everything written to it, so tests can drive the real Agent and
// AgentKey code paths without a live agent.
type replayConn struct {
	resp    []byte // remaining recorded response bytes to serve
	written bytes.Buffer
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.resp) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.resp)
	c.resp = c.resp[n:]
	return n, nil
}

func (c *replayConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return replayAddr{} }
func (c *replayConn) RemoteAddr() net.Addr             { return replayAddr{} }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

type replayAddr struct{}

func (replayAddr) Network() string { return "replay" }
func (replayAddr) String() string  { return "replay" }

// readGolden reads a golden agent message from testdata, failing the test if
// it is missing. A missing file almost always means the golden values have
// not been recorded yet; see TestRecordAgentGolden.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(agentGoldenDir, name))
	if err != nil {
		t.Fatalf("failed to read golden file %s: %v (re-record with SSH_AGENT_RECORD=1)", name, err)
	}
	return b
}
