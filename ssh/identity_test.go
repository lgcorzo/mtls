// Copyright (c) 2026 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ssh_test

import (
	"testing"

	"github.com/lgcorzo/mtls/ssh"
)

func TestParseIdentity(t *testing.T) {
	t.Parallel()

	for i, test := range parseIdentityTests {
		id, err := ssh.ParseIdentity(test.Identity)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to parse identity %s: %v", i, test.Identity, err)
		}
		if err == nil {
			if test.ShouldFail {
				t.Fatalf("Test %d: parsing %s should have failed", i, test.Identity)
			}
			if s := id.String(); s != test.Identity {
				t.Fatalf("Test %d: identity mismatch: %s != %s", i, s, test.Identity)
			}
		}
	}
}

func TestIdentity_MarshalText(t *testing.T) {
	t.Parallel()

	for i, test := range identityMarshalTextTests {
		var id ssh.Identity
		if err := id.UnmarshalText(test.TextInput); err != nil {
			if !test.ShouldFail {
				t.Fatalf("Test %d: failed to unmarshal text: %v", i, err)
			}
		} else {
			if test.ShouldFail {
				t.Fatalf("Test %d: unmarshalling should have failed", i)
			}

			text, err := id.MarshalText()
			if err != nil {
				t.Fatalf("Test %d: failed to marshal text: %v", i, err)
			}
			if string(text) != test.TextOutput {
				t.Fatalf("Test %d: text mismatch: %s != %s", i, text, test.TextOutput)
			}
		}
	}
}

func TestIdentity_IsZero(t *testing.T) {
	t.Parallel()

	var id ssh.Identity
	if !id.IsZero() {
		t.Fatal("zero value should be zero")
	}
	if id.String() != "" {
		t.Fatal("zero value string should be empty")
	}

	parsed, err := ssh.ParseIdentity("")
	if err != nil {
		t.Fatalf("failed to parse empty string: %v", err)
	}
	if !parsed.IsZero() {
		t.Fatal("parsed empty string should be zero")
	}
}

func TestIdentity_RoundTrip(t *testing.T) {
	t.Parallel()

	for i, test := range roundTripTests {
		var id1 ssh.Identity
		if err := id1.UnmarshalText(test.Input); err != nil {
			if !test.ShouldFail {
				t.Fatalf("Test %d: failed to unmarshal text: %v", i, err)
			}
			continue
		}

		text, err := id1.MarshalText()
		if err != nil {
			t.Fatalf("Test %d: failed to marshal text: %v", i, err)
		}

		var id2 ssh.Identity
		if err := id2.UnmarshalText(text); err != nil {
			t.Fatalf("Test %d: failed to unmarshal text: %v", i, err)
		}

		if id1.String() != id2.String() {
			t.Fatalf("Test %d: text round trip failed: %s != %s", i, id1.String(), id2.String())
		}
	}
}

var identityMarshalTextTests = []struct {
	TextInput  []byte
	TextOutput string
	ShouldFail bool
}{
	{TextInput: []byte("SHA256:KDH8bQaT2qfX3FX12nCVVSi5uyccqvJYPCcgYD/dUVk"), TextOutput: "SHA256:KDH8bQaT2qfX3FX12nCVVSi5uyccqvJYPCcgYD/dUVk"}, // 0
	{TextInput: []byte("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), TextOutput: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, // 1
	{TextInput: []byte("MD5:abc"), ShouldFail: true},        // 2
	{TextInput: []byte("SHA256:toolong"), ShouldFail: true}, // 3
}

var parseIdentityTests = []struct {
	Identity   string
	ShouldFail bool
}{
	{Identity: ""}, // 0 - empty string should parse as zero value
	{Identity: "SHA256:KDH8bQaT2qfX3FX12nCVVSi5uyccqvJYPCcgYD/dUVk"},

	{Identity: "MD5:d1:6b:59:c3:f2:d6:7b:52:c2:ae:c8:d7:33:3d:83:f4", ShouldFail: true},
	{Identity: "SHA256:KDH8bQaT2qfX3FX12nCVVSi5uyccqvJYPCcgYD/dUV", ShouldFail: true},
}

var roundTripTests = []struct {
	Input      []byte
	ShouldFail bool
}{
	{Input: []byte("SHA256:KDH8bQaT2qfX3FX12nCVVSi5uyccqvJYPCcgYD/dUVk")},
	{Input: []byte("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
}
