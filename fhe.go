//go:build openfhe

package kbucket

import (
	"errors"
	"fmt" // Import fmt for error formatting

	"github.com/dozyio/openfhe-go/openfhe"
)

// MaxCPL is the size of our query vector.
// Simulation of a 10M peer network shows a max CPL of 20, with a
// theoretical max of ~23. MaxCPL=24 fully supporting networks up to 16.7M
// peers. Networks larger than this will become slightly less efficient at the
// very deepest levels.
const MaxCPL = 24

// ErrFHENotEnabled is returned when FHE operations are attempted without FHE context
var ErrFHENotEnabled = errors.New("FHE is not enabled for this routing table")

type FHEContext struct {
	cc      *openfhe.CryptoContext
	kp      *openfhe.KeyPair
	params  *openfhe.ParamsBGV
	ringDim int // <-- ADD THIS FIELD
}

// NewFHEContext initializes BGV context for integer packing.
func NewFHEContext() (*FHEContext, error) {
	params, err := openfhe.NewParamsBGVrns()
	if err != nil {
		return nil, err
	}

	params.SetPlaintextModulus(65537)
	params.SetMultiplicativeDepth(1)
	params.SetScalingTechnique(openfhe.FIXEDMANUAL)

	cc, err := openfhe.NewCryptoContextBGV(params)
	if err != nil {
		return nil, err
	}

	// Enable features: Encryption + SIMD (Packing)
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)

	// --- FIX: Get and store the Ring Dimension ---
	// For BGV, the number of slots is equal to the ring dimension
	ringDim := cc.GetRingDimension()

	return &FHEContext{cc: cc, params: params, ringDim: int(ringDim)}, nil
}

// GenerateKeys generates the client's keypair and server's evaluation key.
func (ctx *FHEContext) GenerateKeys() error {
	kp, err := ctx.cc.KeyGen()
	if err != nil {
		return err
	}
	ctx.kp = kp

	// Generate MultKey (Evaluation Key) for the server to perform multiplication
	ctx.cc.EvalMultKeyGen(kp)

	return nil
}

// GenerateKeysWithRotation generates keys including rotation keys for packed PIR.
// This is required for the optimized single-ciphertext packed PIR approach.
func (ctx *FHEContext) GenerateKeysWithRotation() error {
	kp, err := ctx.cc.KeyGen()
	if err != nil {
		return err
	}
	ctx.kp = kp

	// Generate MultKey (Evaluation Key) for the server to perform multiplication
	ctx.cc.EvalMultKeyGen(kp)

	// Generate rotation keys for packed PIR:
	// - Positive rotations (i) for extracting slots (rotate LEFT to move slot[i] to slot[0])
	// - Negative rotations (powers of 2) for replication via doubling (rotate RIGHT to replicate)
	indexList := make([]int32, 0, MaxCPL*2)

	// Add positive rotations for slot extraction (rotate LEFT)
	for i := 0; i < MaxCPL; i++ {
		indexList = append(indexList, int32(i))
	}

	// Add negative rotations for slot replication (doubling: -1, -2, -4, -8, -16, ...)
	// We need up to ringDim/2 in the worst case, but powers of 2 up to ringDim are sufficient
	for shift := int32(1); shift < int32(ctx.ringDim); shift *= 2 {
		indexList = append(indexList, -shift)
	}

	err = ctx.cc.EvalRotateKeyGen(kp, indexList)
	if err != nil {
		return fmt.Errorf("failed to generate rotation keys: %w", err)
	}

	return nil
}

// Close releases FHE resources.
func (ctx *FHEContext) Close() {
	if ctx.params != nil {
		ctx.params.Close()
	}
	// Note: openfhe-go bindings should handle GC for kp and cc
}

// CreateQueryVector generates the "One-Hot" encrypted vector based on CPL.
func (ctx *FHEContext) CreateQueryVector(cpl int) ([]*openfhe.Ciphertext, error) {
	if cpl < 0 {
		cpl = 0 // Ensure CPL is not negative
	}
	if cpl >= MaxCPL {
		cpl = MaxCPL - 1 // Clamp to the last index
	}

	vector := make([]*openfhe.Ciphertext, MaxCPL)

	// --- FIX: Create full vectors of 0s or 1s ---
	fullZeroVector := make([]int64, ctx.ringDim) // Already all 0s

	fullOneVector := make([]int64, ctx.ringDim)
	for i := 0; i < ctx.ringDim; i++ {
		fullOneVector[i] = 1
	}

	// Pre-create the two plaintexts we need
	ptZero, err := ctx.cc.MakePackedPlaintext(fullZeroVector)
	if err != nil {
		return nil, fmt.Errorf("failed to make zero plaintext: %w", err)
	}
	defer ptZero.Close()

	ptOne, err := ctx.cc.MakePackedPlaintext(fullOneVector)
	if err != nil {
		return nil, fmt.Errorf("failed to make one plaintext: %w", err)
	}
	defer ptOne.Close()

	for i := 0; i < MaxCPL; i++ {
		var ptToEncrypt *openfhe.Plaintext
		if i == cpl {
			ptToEncrypt = ptOne
		} else {
			ptToEncrypt = ptZero
		}

		ct, err := ctx.cc.Encrypt(ctx.kp, ptToEncrypt)
		if err != nil {
			return nil, err
		}
		vector[i] = ct
	}
	return vector, nil
}

// DecryptConnectablePeers decrypts the PIR response.
func (ctx *FHEContext) DecryptConnectablePeers(ct *openfhe.Ciphertext) ([]ConnectablePeer, error) {
	pt, err := ctx.cc.Decrypt(ctx.kp, ct)
	if err != nil {
		return nil, err
	}
	defer pt.Close()

	// Unpack int64s
	packedData, err := pt.GetPackedValue()
	if err != nil {
		return nil, err
	}

	// Deserialize back to structs
	return DeserializeConnectablePeers(packedData)
}

// CreateQueryVectorPacked creates a single packed ciphertext query (optimized version).
// This uses SIMD slots to encode the one-hot vector in a single ciphertext instead of 24.
// Requires rotation keys to be generated via GenerateKeysWithRotation().
func (ctx *FHEContext) CreateQueryVectorPacked(cpl int) (*openfhe.Ciphertext, error) {
	if cpl < 0 {
		cpl = 0 // Ensure CPL is not negative
	}
	if cpl >= MaxCPL {
		cpl = MaxCPL - 1 // Clamp to the last index
	}

	// Create one-hot vector in slots
	oneHotVector := make([]int64, ctx.ringDim)
	oneHotVector[cpl] = 1 // Only the CPL slot is 1, rest are 0

	// Pack into plaintext
	pt, err := ctx.cc.MakePackedPlaintext(oneHotVector)
	if err != nil {
		return nil, fmt.Errorf("failed to make packed plaintext: %w", err)
	}
	defer pt.Close()

	// Single encryption
	ct, err := ctx.cc.Encrypt(ctx.kp, pt)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

// CreateQueryVectorGreedy creates a one-hot query vector for the Greedy Adaptive method.
// This is identical to CreateQueryVectorPacked - it creates a single packed ciphertext
// with a 1 at the target CPL position and 0s elsewhere.
func (ctx *FHEContext) CreateQueryVectorGreedy(targetCPL int) (*openfhe.Ciphertext, error) {
	if targetCPL < 0 {
		targetCPL = 0
	}
	if targetCPL >= MaxCPL {
		targetCPL = MaxCPL - 1
	}

	// Create one-hot vector
	vec := make([]int64, ctx.ringDim)
	vec[targetCPL] = 1

	pt, err := ctx.cc.MakePackedPlaintext(vec)
	if err != nil {
		return nil, fmt.Errorf("failed to make plaintext: %w", err)
	}
	defer pt.Close()

	return ctx.cc.Encrypt(ctx.kp, pt)
}

// DecryptGreedyAdaptiveResponse handles multi-ring responses from GetBucketPIRGreedyAdaptive.
// It decrypts each ciphertext, concatenates the data, and deserializes using dense packing.
func (ctx *FHEContext) DecryptGreedyAdaptiveResponse(responses []*openfhe.Ciphertext) ([]ConnectablePeer, error) {
	var allPackedInts []int64

	for _, ct := range responses {
		pt, err := ctx.cc.Decrypt(ctx.kp, ct)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt response: %w", err)
		}

		vals, err := pt.GetPackedValue()
		pt.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to get packed value: %w", err)
		}

		// Append to stream
		allPackedInts = append(allPackedInts, vals...)
	}

	// Deserialize the continuous stream
	// The data starts at index 0 because of the Greedy Overlap strategy
	return DeserializeConnectablePeersDense(allPackedInts)
}
