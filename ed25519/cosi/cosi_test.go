// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cosi

import (
	//"encoding/hex"
	"testing"

	//"golang.org/x/crypto/ed25519"
	"github.com/bford/golang-x-crypto/ed25519"
)

type constReader struct{ val byte }

func (cr constReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = cr.val
	}
	return len(buf), nil
}

func testCosign(t *testing.T, message []byte, priKey []ed25519.PrivateKey,
		cos *Cosigners) []byte {

	n := len(priKey)

	aggK := cos.AggregatePublicKey()

	// Create the individual commits and corresponding secrets
	// (these would be done by the individual participants in practice)
	commit := make([]Commitment, n)
	secret := make([]*Secret, n)
	for i := range commit {
		commit[i], secret[i], _ = Commit(nil)
	}

	// Leader: combine the individual commits into an aggregate commit
	aggR := cos.AggregateCommit(commit)

	// Create the individual signature parts
	sigpart := make([]SignaturePart, n)
	for i := range sigpart {
		sigpart[i] = Cosign(priKey[i], secret[i], message, aggK, aggR)

		// verify each part individually
		if !cos.VerifyPart(message, aggR, i, commit[i], sigpart[i]) {
			t.Errorf("signature part %d rejected ", i)
		}
	}

	// Leader: combine the signature parts into a collective signature
	sig := cos.AggregateSignature(aggR, sigpart)
	return sig
}

func TestSignVerify(t *testing.T) {

	// Create a number of distinct keypairs
	n := 10
	pubKey := make([]ed25519.PublicKey, n)
	priKey := make([]ed25519.PrivateKey, n)
	for i := range pubKey {
		pubKey[i], priKey[i], _ = ed25519.GenerateKey(constReader{byte(i)})
	}
	cosigners := NewCosigners(pubKey) // enable all

	// collectively sign a test message
	message := []byte("test message")
	sig := testCosign(t, message, priKey, cosigners)
	if !cosigners.Verify(message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if cosigners.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}

	// now collectively sign with only a partial cosigners set
	cosigners.SetMaskBit(5, Disabled)
	sig = testCosign(t, message, priKey, cosigners)
	if cosigners.Verify(message, sig) {
		t.Errorf("signature with too few cosigners accepted")
	}

	// now reduce the verification threshold
	cosigners.SetPolicy(ThresholdPolicy(n-1))
	if !cosigners.Verify(message, sig) {
		t.Errorf("valid threshold not accepted")
	}

	// now remove another cosigner and make sure it breaks again
	cosigners.SetMaskBit(7, Disabled)
	sig = testCosign(t, message, priKey, cosigners)
	if cosigners.Verify(message, sig) {
		t.Errorf("signature with too few cosigners accepted")
	}
}

/* XXX 
func BenchmarkSigning(b *testing.B) {
	var zero zeroReader
	_, priv, err := ed25519.GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(priv, message)
	}
}

func BenchmarkVerification(b *testing.B) {
	var zero zeroReader
	pub, priv, err := ed25519.GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := Sign(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, message, signature)
	}
}
*/
