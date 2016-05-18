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

var pubKeys []ed25519.PublicKey
var priKeys []ed25519.PrivateKey

var rightMessage = []byte("test message")
var wrongMessage = []byte("wrong message")

func genKeys(n int) {
	for len(priKeys) < n {
		i := len(priKeys)
		pub, pri, _ := ed25519.GenerateKey(constReader{byte(i)})
		pubKeys = append(pubKeys, pub)
		priKeys = append(priKeys, pri)
	}
}

func testCosign(tb testing.TB, message []byte, priKey []ed25519.PrivateKey,
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
			tb.Errorf("signature part %d rejected ", i)
		}
	}

	// Leader: combine the signature parts into a collective signature
	sig := cos.AggregateSignature(aggR, sigpart)
	return sig
}

func TestSignVerify(t *testing.T) {

	// Create a number of distinct keypairs
	n := 10
	genKeys(n)
	cosigners := NewCosigners(pubKeys[:n], nil) // all enabled by default
	if cosigners.CountTotal() != n {
		t.Errorf("cosigners reports incorrect number of public keys")
	}
	if cosigners.CountEnabled() != n {
		t.Errorf("cosigners reports incorrect number of enabled keys")
	}

	// collectively sign a test message
	sig := testCosign(t, rightMessage, priKeys[:n], cosigners)
	if !cosigners.Verify(rightMessage, sig) {
		t.Errorf("valid signature rejected")
	}

	if cosigners.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}

	// now collectively sign with only a partial cosigners set
	cosigners.SetMaskBit(5, Disabled)
	if cosigners.CountEnabled() != n-1 {
		t.Errorf("cosigners reports incorrect number of enabled keys")
	}
	sig = testCosign(t, rightMessage, priKeys[:n], cosigners)
	if cosigners.Verify(rightMessage, sig) {
		t.Errorf("signature with too few cosigners accepted")
	}

	// now reduce the verification threshold
	cosigners.SetPolicy(ThresholdPolicy(n - 1))
	if !cosigners.Verify(rightMessage, sig) {
		t.Errorf("valid threshold not accepted")
	}

	// now remove another cosigner and make sure it breaks again
	cosigners.SetMaskBit(7, Disabled)
	if cosigners.CountEnabled() != n-2 {
		t.Errorf("cosigners reports incorrect number of enabled keys")
	}
	sig = testCosign(t, rightMessage, priKeys[:n], cosigners)
	if cosigners.Verify(rightMessage, sig) {
		t.Errorf("signature with too few cosigners accepted")
	}
}

var testSig1, testSig10, testSig100, testSig1000 []byte
var testInd1, testInd10, testInd100, testInd1000 [][]byte

// Generate n individual signatures with standard Ed25519 signing,
// for comparison.
func genInd(tb testing.TB, n int) [][]byte {
	genKeys(n)
	sigs := make([][]byte, n)
	for i := range sigs {
		sigs[i] = ed25519.Sign(priKeys[i], rightMessage)
	}
	return sigs
}

func benchSign(b *testing.B, nsigners int) {
	genKeys(nsigners)                                  // make sure we have enough keypairs
	cosigners := NewCosigners(pubKeys[:nsigners], nil) // all enabled by default
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testCosign(b, rightMessage, priKeys[:nsigners], cosigners)
	}
}

func benchSignInd(b *testing.B, nsigners int) {
	genKeys(nsigners)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		genInd(b, nsigners)
	}
}

func benchVerifyCached(b *testing.B, nsigners int) {
	genKeys(nsigners)                                  // make sure we have enough keypairs
	cosigners := NewCosigners(pubKeys[:nsigners], nil) // all enabled
	sig := testCosign(b, rightMessage, priKeys[:nsigners], cosigners)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !cosigners.Verify(rightMessage, sig) {
			b.Errorf("%d-signer signature rejected", nsigners)
		}
	}
}

func benchVerifyWorst(b *testing.B, nsigners int) {
	genKeys(nsigners)                                  // make sure we have enough keypairs
	cosigners := NewCosigners(pubKeys[:nsigners], nil) // all enabled
	sig := testCosign(b, rightMessage, priKeys[:nsigners], cosigners)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(pubKeys[:nsigners], nil, rightMessage, sig) {
			b.Errorf("%d-signer signature rejected", nsigners)
		}
	}
}

func benchVerifyInd(b *testing.B, nsigners int) {
	genKeys(nsigners)
	sigs := genInd(b, nsigners)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range sigs {
			if !ed25519.Verify(pubKeys[j], rightMessage, sigs[j]) {
				b.Errorf("signer %d's signature rejected", j)
			}
		}
	}
}

// Signing benchmarks

func BenchmarkSign1Collective(b *testing.B) {
	benchSign(b, 1)
}

func BenchmarkSign1Individual(b *testing.B) {
	benchSignInd(b, 1)
}

func BenchmarkSign10Collective(b *testing.B) {
	benchSign(b, 10)
}

func BenchmarkSign10Individual(b *testing.B) {
	benchSignInd(b, 10)
}

func BenchmarkSign100Collective(b *testing.B) {
	benchSign(b, 100)
}

func BenchmarkSign100Individual(b *testing.B) {
	benchSignInd(b, 100)
}

func BenchmarkSign1000Collective(b *testing.B) {
	benchSign(b, 1000)
}

func BenchmarkSign1000Individual(b *testing.B) {
	benchSignInd(b, 1000)
}

// Verification benchmarks

func BenchmarkVerify1CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 1)
}

func BenchmarkVerify1CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 1)
}

func BenchmarkVerify1Individual(b *testing.B) {
	benchVerifyInd(b, 1)
}

func BenchmarkVerify10CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 10)
}

func BenchmarkVerify10CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 10)
}

func BenchmarkVerify10Individual(b *testing.B) {
	benchVerifyInd(b, 10)
}

func BenchmarkVerify100CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 100)
}

func BenchmarkVerify100CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 100)
}

func BenchmarkVerify100Individual(b *testing.B) {
	benchVerifyInd(b, 100)
}

func BenchmarkVerify1000CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 1000)
}

func BenchmarkVerify1000CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 1000)
}

func BenchmarkVerify1000Individual(b *testing.B) {
	benchVerifyInd(b, 1000)
}
