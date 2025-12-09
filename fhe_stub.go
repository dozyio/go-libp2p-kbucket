//go:build !openfhe

package kbucket

import "errors"

// This is a stub implementation of FHE functionality that is used when
// the openfhe build tag is not set or when OpenFHE C++ library is not installed.
//
// To use the real FHE implementation:
// 1. Install OpenFHE C++ library (https://github.com/openfheorg/openfhe-development)
// 2. Build with: go build -tags openfhe
//
// This stub allows the kbucket library to compile and work normally
// without FHE support, returning appropriate errors when FHE functions are called.

var (
	errFHEStub = errors.New("FHE support not compiled in; rebuild with -tags openfhe and install OpenFHE C++ library")

	// ErrFHENotEnabled is returned when FHE operations are attempted without FHE context
	ErrFHENotEnabled = errors.New("FHE is not enabled for this routing table")
	// ErrInvalidCiphertext is returned when ciphertext operations fail
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// FHEContext stub - does nothing when FHE is not enabled
type FHEContext struct{}

// EncryptedID stub
type EncryptedID struct{}

func NewFHEContext() (*FHEContext, error) {
	return nil, errFHEStub
}

func (ctx *FHEContext) GenerateKeys() error {
	return errFHEStub
}

func (ctx *FHEContext) Close() {}

func (ctx *FHEContext) EncryptPeerID(id ID) (*EncryptedID, error) {
	return nil, errFHEStub
}

func (ctx *FHEContext) XORWithPlaintext(encID *EncryptedID, plaintextID ID) (*EncryptedID, error) {
	return nil, errFHEStub
}

func (ctx *FHEContext) DecryptBits(encID *EncryptedID) (ID, error) {
	return nil, errFHEStub
}

func (encID *EncryptedID) Close() {}
