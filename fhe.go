//go:build openfhe

package kbucket

import (
	"errors"
	"fmt"

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
	CC      *openfhe.CryptoContext
	KP      *openfhe.KeyPair
	params  *openfhe.ParamsBGV
	ringDim int
}

// NewFHEContext initializes BGV context for integer packing.
func NewFHEContext() (*FHEContext, error) {
	params, err := openfhe.NewParamsBGVrns()
	if err != nil {
		return nil, err
	}

	params.SetPlaintextModulus(65537)
	params.SetMultiplicativeDepth(1)
	params.SetRingDim(8192)
	params.SetScalingTechnique(openfhe.FIXEDMANUAL)
	// params.SetKeySwitchTechnique(openfhe.BV)

	cc, err := openfhe.NewCryptoContextBGV(params)
	if err != nil {
		return nil, err
	}

	// Enable features: Encryption + SIMD (Packing)
	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)

	ringDim := cc.GetRingDimension()

	return &FHEContext{CC: cc, params: params, ringDim: int(ringDim)}, nil
}

// GenerateKeys generates the client's keypair and server's evaluation key.
func (ctx *FHEContext) GenerateKeys() error {
	kp, err := ctx.CC.KeyGen()
	if err != nil {
		return err
	}
	ctx.KP = kp

	// Generate MultKey (Evaluation Key) for the server to perform multiplication
	ctx.CC.EvalMultKeyGen(kp)

	return nil
}

// GenerateKeysWithRotation generates keys including rotation keys for packed PIR.
// This is required for the optimized single-ciphertext packed PIR approach.
func (ctx *FHEContext) GenerateKeysWithRotation() error {
	kp, err := ctx.CC.KeyGen()
	if err != nil {
		return err
	}
	ctx.KP = kp

	// Generate MultKey (Evaluation Key) for the server to perform multiplication
	ctx.CC.EvalMultKeyGen(kp)

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

	fmt.Printf("GenerateKeysWithRotation indexList (%d): %v\n", len(indexList), indexList)

	err = ctx.CC.EvalRotateKeyGen(kp, indexList)
	if err != nil {
		return fmt.Errorf("failed to generate rotation keys: %w", err)
	}

	return nil
}

// GenerateKeysPowerOfTwo generates a reduced set of rotation keys (powers of two only).
// This reduces key size by ~50% compared to GenerateKeysWithRotation.
func (ctx *FHEContext) GenerateKeysPowerOfTwo() error {
	kp, err := ctx.CC.KeyGen()
	if err != nil {
		return err
	}
	ctx.KP = kp

	// Generate MultKey (Evaluation Key)
	ctx.CC.EvalMultKeyGen(kp)

	indexList := make([]int32, 0)

	// 1. Positive Powers of 2 (for CPL extraction)
	// Instead of 0..MaxCPL, we only generate 1, 2, 4, 8, 16...
	for i := 1; i < MaxCPL; i *= 2 {
		indexList = append(indexList, int32(i))
	}

	// 2. Negative Powers of 2 (for replication/doubling)
	// We still need these for the efficient doubling phase.
	for shift := int32(1); shift < int32(ctx.ringDim); shift *= 2 {
		indexList = append(indexList, -shift)
	}

	fmt.Printf("GenerateKeysPowerOfTwo: indexList (%d): %v\n", len(indexList), indexList)

	err = ctx.CC.EvalRotateKeyGen(kp, indexList)
	if err != nil {
		return fmt.Errorf("failed to generate rotation keys: %w", err)
	}

	return nil
}

// GenerateKeysMinimal generates only the unit step keys.
// This results in the smallest possible keys size
func (ctx *FHEContext) GenerateKeysMinimal() error {
	kp, err := ctx.CC.KeyGen()
	if err != nil {
		return err
	}
	ctx.KP = kp

	// Generate MultKey (Evaluation Key)
	ctx.CC.EvalMultKeyGen(kp)

	// ONLY generate keys for +1 (Left) and -1 (Right)
	// We will compose all other rotations by repeating these.
	indexList := []int32{1, -1}

	err = ctx.CC.EvalRotateKeyGen(kp, indexList)
	if err != nil {
		return fmt.Errorf("failed to generate rotation keys: %w", err)
	}

	return nil
}

// RotateComposite rotates a ciphertext by k positions using only power-of-two keys.
// It decomposes k (e.g., 23) into powers of 2 (16 + 4 + 2 + 1) and applies them sequentially.
func (ctx *FHEContext) RotateComposite(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
	if k == 0 {
		return ct.Clone()
	}

	current := ct
	isFirst := true

	// Decompose k into powers of 2
	for shift := 1; shift <= k; shift *= 2 {
		if (k & shift) != 0 {
			// Apply rotation for this bit
			next, err := ctx.CC.EvalRotate(current, int32(shift))
			if err != nil {
				// If we failed and have intermediate results, close them
				if !isFirst {
					current.Close()
				}
				return nil, err
			}

			// Clean up intermediate results (but never close the original input 'ct')
			if !isFirst {
				current.Close()
			}
			current = next
			isFirst = false
		}
	}
	return current, nil
}

// RotateIterative rotates a ciphertext by k positions using only the +1 or -1 keys.
// This trades computation time (latency) for massive bandwidth savings.
func (ctx *FHEContext) RotateIterative(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
	if k == 0 {
		return ct.Clone()
	}

	// Determine direction and unit step
	step := int32(1) // Rotate Left (+1)
	count := k
	if k < 0 {
		step = -1 // Rotate Right (-1)
		count = -k
	}

	current := ct

	// Apply the rotation 'count' times
	// e.g., Rotate(4) = Rotate(1) -> Rotate(1) -> Rotate(1) -> Rotate(1)
	for i := 0; i < count; i++ {
		// 1. Perform one unit step
		next, err := ctx.CC.EvalRotate(current, step)
		if err != nil {
			// If we fail partway, clean up intermediate ciphertexts
			if i > 0 {
				current.Close() // Only close if we own it (not the input ct)
			}
			return nil, err
		}

		// 2. Clean up the previous step's memory
		if i > 0 {
			current.Close()
		}
		current = next
	}

	return current, nil
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

	fullZeroVector := make([]int64, ctx.ringDim) // Already all 0s

	fullOneVector := make([]int64, ctx.ringDim)
	for i := 0; i < ctx.ringDim; i++ {
		fullOneVector[i] = 1
	}

	// Pre-create the two plaintexts we need
	ptZero, err := ctx.CC.MakePackedPlaintext(fullZeroVector)
	if err != nil {
		return nil, fmt.Errorf("failed to make zero plaintext: %w", err)
	}
	defer ptZero.Close()

	ptOne, err := ctx.CC.MakePackedPlaintext(fullOneVector)
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

		ct, err := ctx.CC.Encrypt(ctx.KP, ptToEncrypt)
		if err != nil {
			return nil, err
		}
		vector[i] = ct
	}
	return vector, nil
}

// DecryptConnectablePeers decrypts the PIR response.
func (ctx *FHEContext) DecryptConnectablePeers(ct *openfhe.Ciphertext) ([]ConnectablePeer, error) {
	pt, err := ctx.CC.Decrypt(ctx.KP, ct)
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
	pt, err := ctx.CC.MakePackedPlaintext(oneHotVector)
	if err != nil {
		return nil, fmt.Errorf("failed to make packed plaintext: %w", err)
	}
	defer pt.Close()

	// Single encryption
	ct, err := ctx.CC.Encrypt(ctx.KP, pt)
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

	pt, err := ctx.CC.MakePackedPlaintext(vec)
	if err != nil {
		return nil, fmt.Errorf("failed to make plaintext: %w", err)
	}
	defer pt.Close()

	return ctx.CC.Encrypt(ctx.KP, pt)
}

// DecryptGreedyAdaptiveResponse handles multi-ring responses from GetBucketPIRGreedyAdaptive.
// It decrypts each ciphertext, concatenates the data, and deserializes using dense packing.
func (ctx *FHEContext) DecryptGreedyAdaptiveResponse(responses []*openfhe.Ciphertext) ([]ConnectablePeer, error) {
	var allPackedInts []int64

	for _, ct := range responses {
		pt, err := ctx.CC.Decrypt(ctx.KP, ct)
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
