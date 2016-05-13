// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519 implements the Ed25519 signature algorithm. See
// http://ed25519.cr.yp.to/.
//
// These functions are also compatible with the “Ed25519” function defined in
// https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05.
package cosi

// This code is a port of the public domain, “ref10” implementation of ed25519
// from SUPERCOP.

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"io"
	"strconv"
	"math/big"
	//"encoding/hex"

	"golang.org/x/crypto/ed25519/internal/edwards25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
)

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey []byte


type MaskBit bool
const (
	Enabled MaskBit = false
	Disabled MaskBit = true
)

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}


// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (publicKey PublicKey, privateKey PrivateKey, err error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	privateKey = make([]byte, PrivateKeySize)
	publicKey = make([]byte, PublicKeySize)
	_, err = io.ReadFull(rand, privateKey[:32])
	if err != nil {
		return nil, nil, err
	}

	digest := sha512.Sum512(privateKey[:32])
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	copy(privateKey[32:], publicKeyBytes[:])
	copy(publicKey, publicKeyBytes[:])

	return publicKey, privateKey, nil
}


// Policy represents a fully customizable cosigning policy
// deciding what cosigner sets are and aren't sufficient
// for a collective signature to be considered valid.
type Policy interface {
	Check(cosigners *Cosigners) bool
}

// The default, conservative policy
// just requires all participants to have signed.
type fullPolicy struct{}
func (_ fullPolicy) Check(cosigners *Cosigners) bool {
	return cosigners.CountEnabled() == cosigners.CountTotal()
}

type thresPolicy struct{ t int }
func (p thresPolicy) Check(cosigners *Cosigners) bool {
	return cosigners.CountEnabled() >= p.t
}
func ThresholdPolicy(threshold int) Policy {
	return &thresPolicy{threshold}
}

// XXX add simple threshold policy


// Secret represents a one-time random secret used
// in collectively signing a single message.
type Secret struct {
	reduced [32]byte
	valid bool
}

func Commit(rand io.Reader) ([]byte, *Secret, error) {

	var secretFull [64]byte
	if rand == nil {
		rand = cryptorand.Reader
	}
	_, err := io.ReadFull(rand, secretFull[:])
	if err != nil {
		return nil, nil, err
	}

	var secret Secret
	edwards25519.ScReduce(&secret.reduced, &secretFull)
	secret.valid = true

	// compute R, the individual Schnorr commit to our one-time secret
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &secret.reduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)
	return encodedR[:], &secret, nil
}

// Cosign signs the message with privateKey and returns a partial signature. It will
// panic if len(privateKey) is not PrivateKeySize.
func Cosign(privateKey PrivateKey, secret *Secret,
		message, aggregateK, aggregateR []byte) []byte {

	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	if l := len(aggregateR); l != PublicKeySize {
		panic("ed25519: bad aggregateR length: " + strconv.Itoa(l))
	}
	if !secret.valid {
		panic("ed25519: you must use a cosigning Secret only once")
	}

	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1 [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	var hramDigest [64]byte
	h.Reset()
	h.Write(aggregateR)
	h.Write(aggregateK)
	h.Write(message)
	h.Sum(hramDigest[:0])

	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	// Produce our individual contribution to the collective signature
	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey,
				&secret.reduced)

	// Erase the one-time secret and make darn sure it gets used only once,
	// even if a buggy caller invokes Cosign twice after a single Commit
	secret.reduced = [32]byte{}
	secret.valid = false

	return s[:]	// individual partial signature
}


type Cosigners struct {
	// list of all cosigners' public keys in internalized form
	keys []edwards25519.ExtendedGroupElement

	// bit-vector of *disabled* cosigners
	mask big.Int

	// cached aggregate of all enabled cosigners' public keys
	aggr edwards25519.ExtendedGroupElement

	// cosigner-presence policy for checking signatures
	policy Policy
}

func NewCosigners(publicKeys []PublicKey, mask []byte) *Cosigners {
	var publicKeyBytes [32]byte
	cos := &Cosigners{}
	cos.keys = make([]edwards25519.ExtendedGroupElement, len(publicKeys))
	for i, publicKey := range publicKeys {
		copy(publicKeyBytes[:], publicKey)
		if !cos.keys[i].FromBytes(&publicKeyBytes) {
			return nil
		}
	}
	cos.SetMask(mask)
	cos.policy = &fullPolicy{}
	return cos
}

func (cos *Cosigners) CountTotal() int {
	return len(cos.keys)
}

func (cos *Cosigners) CountEnabled() int {
	// Yes, we could count zero-bits much more efficiently...
	count := 0
	for i := range cos.keys {
		if cos.MaskBit(i) == Enabled {
			count++
		}
	}
	return count
}

//func (cos *Cosigners) PublicKeys() []PublicKey {
//	return cos.keys
//}

func (cos *Cosigners) SetMask(mask []byte) {
	cos.mask.SetInt64(0)
	cos.aggr.Zero()
	masklen := len(mask)
	for i := range cos.keys {
		if (i>>3 < masklen) && (mask[i>>3] & (1 << uint(i&7)) != 0) {
			cos.mask.SetBit(&cos.mask, i, 1)	// disable
		} else {
			cos.aggr.Add(&cos.aggr, &cos.keys[i])	// enable
		}
	}
}

// Return the current cosigner disable-mask as a little-endian bit-vector.
func (cos *Cosigners) Mask() []byte {
	mask := make([]byte, (len(cos.keys)+7)>>3)
	for i := 0; i < len(cos.keys); i++ {
		if cos.mask.Bit(i) > 0 {
			mask[i>>3] |= 1 << uint(i&7)
		}
	}
	return mask
}

// Return the length in bytes of a disable-mask for this cosigner list.
func (cos *Cosigners) MaskLen() int {
	return (len(cos.keys)+7) >> 3
}

// Enable or disable a given signer
func (cos *Cosigners) SetMaskBit(signer int, bit MaskBit) {
	if bit == Disabled {				// disable
		if cos.mask.Bit(signer) == 0 {		// was enabled
			cos.mask.SetBit(&cos.mask, signer, 1)
			cos.aggr.Sub(&cos.aggr, &cos.keys[signer])
		}
	} else {					// enable
		if cos.mask.Bit(signer) == 1 {		// was disabled
			cos.mask.SetBit(&cos.mask, signer, 0)
			cos.aggr.Add(&cos.aggr, &cos.keys[signer])
		}
	}
}

func (cos *Cosigners) MaskBit(signer int) (bit MaskBit) {
	return cos.mask.Bit(signer) != 0
}

// Return the aggregate public key for the currently-enabled cosigners.
func (cos *Cosigners) AggregatePublicKey() PublicKey {
	var keyBytes [32]byte
	cos.aggr.ToBytes(&keyBytes)
	return keyBytes[:]
}

// Combine signing commitments from all enabled cosigners
// to form a single aggregate commitment.
func (cos *Cosigners) AggregateCommit(commits [][]byte) []byte {

	var aggR, indivR edwards25519.ExtendedGroupElement
	var commitBytes [32]byte

	aggR.Zero()
	for i := range cos.keys {
		if cos.MaskBit(i) == Disabled {
			continue
		}

		if l := len(commits[i]); l != PublicKeySize {
			return nil
		}
		copy(commitBytes[:], commits[i])
		if !indivR.FromBytes(&commitBytes) {
			return nil
		}
		aggR.Add(&aggR, &indivR)
	}

	var aggRBytes [32]byte
	aggR.ToBytes(&aggRBytes)
	return aggRBytes[:]
}

var scOne = [32]byte{1}

// Combine individual signature parts into a complete aggregate signature.
func (cos *Cosigners) AggregateSignature(aggregateR []byte, sigParts [][]byte) []byte {

	if l := len(aggregateR); l != PublicKeySize {
		panic("ed25519: bad aggregateR length: " + strconv.Itoa(l))
	}

	var aggS, indivS [32]byte
	for i := range cos.keys {
		if cos.MaskBit(i) == Disabled {
			continue
		}

		if l := len(sigParts[i]); l != 32 {
			return nil
		}
		copy(indivS[:], sigParts[i])
		edwards25519.ScMulAdd(&aggS, &aggS, &scOne, &indivS)
	}

	mask := cos.Mask()
	cosigSize := SignatureSize + len(mask)
	signature := make([]byte, cosigSize)
	copy(signature[:], aggregateR)
	copy(signature[32:64], aggS[:])
	copy(signature[64:], mask)

	return signature
}

// Verify an individual signature part
func (cos *Cosigners) VerifyPart(message, aggR []byte,
				signer int, indR, indS []byte) bool {

	return cos.verify(message, aggR, indR, indS, cos.keys[signer])
}

// Verify reports whether sig is a valid signature of message
// collectively signed by the enabled cosigners.
// XXX deal with the mask
func (cos *Cosigners) Verify(message, sig []byte) bool {

	cosigSize := SignatureSize + cos.MaskLen()
	if len(sig) != cosigSize {
		return false
	}

	// Update our mask to reflect which cosigners actually signed
	cos.SetMask(sig[64:])

	// Check that this prepresents a sufficient set of signers
	if !cos.policy.Check(cos) {
		return false
	}

	return cos.verify(message, sig[:32], sig[:32], sig[32:64], cos.aggr)
}

func (cos *Cosigners) verify(message, aggR, sigR, sigS []byte,
		sigA edwards25519.ExtendedGroupElement) bool {

	if len(sigR) != 32 || len(sigS) != 32 || sigS[31]&224 != 0 {
		return false
	}

	// Compute the digest against aggregate public key and commit
	var aggK [32]byte
	cos.aggr.ToBytes(&aggK)

	h := sha512.New()
	h.Write(aggR)
	h.Write(aggK[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	// The public key used for checking is whichever part was signed
	edwards25519.FeNeg(&sigA.X, &sigA.X)
	edwards25519.FeNeg(&sigA.T, &sigA.T)

	var projR edwards25519.ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sigS)
	edwards25519.GeDoubleScalarMultVartime(&projR, &hReduced, &sigA, &b)

	var checkR [32]byte
	projR.ToBytes(&checkR)
	return subtle.ConstantTimeCompare(sigR, checkR[:]) == 1
}

func (cos *Cosigners) SetPolicy(policy Policy) {
	cos.policy = policy	
}

