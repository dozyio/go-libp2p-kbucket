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

	err = params.SetPlaintextModulus(65537)
	if err != nil {
		return nil, err
	}

	err = params.SetMultiplicativeDepth(2)
	if err != nil {
		return nil, err
	}

	err = params.SetRingDim(8192)
	if err != nil {
		return nil, err
	}

	// err = params.SetFirstModSize(60)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// err = params.SetScalingModSize(60)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// err = params.SetDigitSize(30)
	// if err != nil {
	// 	return nil, err
	// }

	// params.SetSecurityLevel(openfhe.HEStdNotSet)
	err = params.SetScalingTechnique(openfhe.FIXEDMANUAL)
	if err != nil {
		return nil, err
	}

	err = params.SetKeySwitchTechnique(openfhe.BV)
	if err != nil {
		return nil, err
	}

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

//	func (ctx *FHEContext) GenerateKeysSparse() error {
//		kp, err := ctx.CC.KeyGen()
//		if err != nil {
//			return err
//		}
//		ctx.KP = kp
//		ctx.CC.EvalMultKeyGen(kp)
//
//		// Only 4 keys: +/-1 and +/-5
//		// This provides a balance: reasonable speed, tiny size.
//		indexList := []int32{1, -1, -32}
//
//		err = ctx.CC.EvalRotateKeyGen(kp, indexList)
//		if err != nil {
//			return fmt.Errorf("failed to generate rotation keys: %w", err)
//		}
//		return nil
//	}
//
//	func (ctx *FHEContext) GenerateKeysSparse() error {
//		kp, err := ctx.CC.KeyGen()
//		if err != nil {
//			return err
//		}
//		ctx.KP = kp
//
//		// No EvalMultKeyGen (Saves ~250KB since we don't multiply ciphertexts)
//
//		// 7 Keys: Base-4 Strategy
//		// Positive (Extraction): 1, 4
//		// Negative (Replication): -1, -4, -16, -64, -256
//		// Total Size: ~0.85 MB
//		indexList := []int32{1, 4, -1, -4, -16, -64, -256}
//
//		err = ctx.CC.EvalRotateKeyGen(kp, indexList)
//		if err != nil {
//			return fmt.Errorf("failed to generate rotation keys: %w", err)
//		}
//
//		return nil
//	}
//
//	func (ctx *FHEContext) GenerateKeysSparse() error {
//		kp, err := ctx.CC.KeyGen()
//		if err != nil {
//			return err
//		}
//		ctx.KP = kp
//
//		// Generate STANDARD Power-of-Two keys (1, 2, 4... 512)
//		// At Ring 2048, these are small (~60KB each).
//		// 12 keys * 60 KB = ~720 KB (Under 1 MB).
//		indexList := make([]int32, 0)
//		for i := 1; i < 24; i *= 2 {
//			indexList = append(indexList, int32(i))
//		}
//		for i := 1; i < 2048; i *= 2 {
//			indexList = append(indexList, int32(-i))
//		}
//
//		return ctx.CC.EvalRotateKeyGen(kp, indexList)
//	}
//
//	func (ctx *FHEContext) GenerateKeysSparse() error {
//		kp, err := ctx.CC.KeyGen()
//		if err != nil {
//			return err
//		}
//		ctx.KP = kp
//
//		// No EvalMultKeyGen (RelinKey not needed for PIR)
//
//		// 5 Keys: {1, -1, -8, -64, -512}
//		// Est Size: 5 * 125KB = ~625 KB
//		indexList := []int32{1, -1, -8, -64, -512}
//
//		err = ctx.CC.EvalRotateKeyGen(kp, indexList)
//		if err != nil {
//			return fmt.Errorf("failed to generate rotation keys: %w", err)
//		}
//		return nil
//	}
//
//	func (ctx *FHEContext) GenerateKeysSparse() error {
//		kp, err := ctx.CC.KeyGen()
//		if err != nil {
//			return err
//		}
//		ctx.KP = kp
//
//		// Note: EvalMultKey (RelinKey) is NOT generated.
//		// It saves ~400 KB and is not needed for PIR (Ciphertext * Plaintext).
//
//		// 5 Keys: {1, -1, -8, -64, -512}
//		indexList := make([]int32, 0)
//		for i := 1; i < 24; i *= 2 {
//			indexList = append(indexList, int32(i))
//		}
//		for i := 1; i < 2048; i *= 2 {
//			indexList = append(indexList, int32(-i))
//		}
//		err = ctx.CC.EvalRotateKeyGen(kp, indexList)
//		if err != nil {
//			return fmt.Errorf("failed to generate rotation keys: %w", err)
//		}
//		return nil
//	}
//
//	func (ctx *FHEContext) GenerateKeysSparse() error {
//		kp, err := ctx.CC.KeyGen()
//		if err != nil {
//			return err
//		}
//		ctx.KP = kp
//
//		indexList := []int32{1, 4, -1, -4, -16, -64, -256}
//
//		return ctx.CC.EvalRotateKeyGen(kp, indexList)
//	}
//
//	func (ctx *FHEContext) GenerateKeysSparse() error {
//		kp, err := ctx.CC.KeyGen()
//		if err != nil {
//			return err
//		}
//		ctx.KP = kp
//
//		// No EvalMultKeyGen needed.
//
//		// STANDARD POWERS OF 2 (12 Keys)
//		// At N=4096, Depth=0: Each key is ~65 KB.
//		// Total Size: 12 * 65 = ~780 KB (Well under 1 MB).
//		// This allows 1-hop rotations for everything.
//		indexList := make([]int32, 0)
//
//		// Extraction keys (Small positive)
//		// We need to cover 0..23. Powers of 2 are sufficient.
//		for i := 1; i < 24; i *= 2 {
//			indexList = append(indexList, int32(i))
//		}
//
//		// Replication keys (Negative powers of 2)
//		// We need to cover 1..2048.
//		for i := 1; i <= 2048; i *= 2 {
//			indexList = append(indexList, int32(-i))
//		}
//
//		err = ctx.CC.EvalRotateKeyGen(kp, indexList)
//		if err != nil {
//			return fmt.Errorf("failed to generate rotation keys: %w", err)
//		}
//		return nil
//	}
// func (ctx *FHEContext) GenerateKeysSparse() error {
// 	kp, err := ctx.CC.KeyGen()
// 	if err != nil {
// 		return err
// 	}
// 	ctx.KP = kp
//
// 	// 12 Keys: Powers of 2
// 	// 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048
// 	// Plus Negatives? Actually, we only need Negatives for Replication.
// 	// We need Positive for Extraction.
//
// 	indexList := []int32{}
//
// 	// Positive (Extraction 0..23): 1, 2, 4, 8, 16
// 	for i := 1; i < 32; i *= 2 {
// 		indexList = append(indexList, int32(i))
// 	}
//
// 	// Negative (Replication 1..2048): -1, -2 ... -2048
// 	for i := 1; i <= 2048; i *= 2 {
// 		indexList = append(indexList, int32(-i))
// 	}
//
// 	// Total Keys: 5 + 12 = 17 Keys.
// 	// Size at Depth 0 (1 prime): ~60KB per key.
// 	// Total: 17 * 60 = ~1020 KB (Just ~1MB).
// 	// If strictly <1MB, remove -2048 (we handle it by 2x -1024).
//
// 	return ctx.CC.EvalRotateKeyGen(kp, indexList)
// }

func (ctx *FHEContext) GenerateKeysSparse() error {
	kp, err := ctx.CC.KeyGen()
	if err != nil {
		return err
	}
	ctx.KP = kp

	// 5 Keys: Base-8 Strategy
	// Size: ~0.63 MB
	indexList := []int32{1, -1, -8, -64, -512}

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

// RotateSparse rotates 'k' using only {1, 5, -1, -5}.
// Max hops for k=23 is 7 (vs 23 for unit steps).
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		// 1. Determine steps
//		unit := int32(1)
//		giant := int32(5)
//
//		// Handle negatives
//		if k < 0 {
//			unit = -1
//			giant = -5
//			k = -k
//		}
//
//		// 2. Greedy decomposition
//		numGiant := k / 5
//		numUnit := k % 5
//
//		current := ct
//
//		// Apply Giant Steps (+/- 5)
//		for i := 0; i < numGiant; i++ {
//			next, err := ctx.CC.EvalRotate(current, giant)
//			if err != nil {
//				return nil, err
//			}
//			if current != ct {
//				current.Close()
//			} // Don't close original input
//			current = next
//		}
//
//		// Apply Unit Steps (+/- 1)
//		for i := 0; i < numUnit; i++ {
//			next, err := ctx.CC.EvalRotate(current, unit)
//			if err != nil {
//				return nil, err
//			}
//			if current != ct {
//				current.Close()
//			}
//			current = next
//		}
//
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		// Target basis
//		unit := int32(1)
//		big := int32(64)
//
//		// Handle Negatives
//		if k < 0 {
//			unit = -1
//			big = -64
//			k = -k
//		}
//
//		// Greedy Decomposition
//		// e.g., 128 -> 2 * 64 (2 hops)
//		// e.g., 32  -> 32 * 1 (32 hops)
//		numBig := k / 64
//		numUnit := k % 64
//
//		current := ct
//		// var err error
//
//		// Apply Big Steps
//		for i := 0; i < numBig; i++ {
//			next, err := ctx.CC.EvalRotate(current, big)
//			if err != nil {
//				return nil, err
//			}
//			if current != ct {
//				current.Close()
//			}
//			current = next
//		}
//
//		// Apply Unit Steps
//		for i := 0; i < numUnit; i++ {
//			next, err := ctx.CC.EvalRotate(current, unit)
//			if err != nil {
//				return nil, err
//			}
//			if current != ct {
//				current.Close()
//			}
//			current = next
//		}
//
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		// We only handle Extraction (k > 0, small) and Replication (k < 0, large) efficiently.
//
//		// Case 1: Positive Shift (Left) - Used for CPL Extraction (0..23)
//		// Strategy: Just use +1 repeated. Max 23 hops. Safe for fresh ciphertext.
//		if k > 0 {
//			current := ct
//			// var err error
//			for i := 0; i < k; i++ {
//				next, err := ctx.CC.EvalRotate(current, 1)
//				if err != nil {
//					return nil, err
//				}
//				if i > 0 {
//					current.Close()
//				}
//				current = next
//			}
//			return current, nil
//		}
//
//		// Case 2: Negative Shift (Right) - Used for Replication (1..2048)
//		// Target T is the magnitude of the right shift
//		T := -k
//
//		// We want to reach T using {-64, -8, -1} and correcting with {+1}
//
//		// Step A: Multiples of 64
//		// Check if flooring or rounding is better?
//		// Note: We lack +8/+64 keys, so we can only correct 'Left' using +1 efficiently for small errors.
//		// Overshooting 64 (requiring Left correction) is only good if the error is small.
//
//		n64 := T / 64
//		rem64 := T % 64
//
//		// Heuristic: If remainder is > 56, it's cheaper to do 1x(-64) and correct with +1s
//		// than to do 7x(-8).
//		if rem64 > 56 {
//			n64++
//			rem64 -= 64 // Negative remainder means we need Left shift (correction)
//		}
//
//		// Step B: Multiples of 8 (for the remainder)
//		// We handle the remaining amount using -8 and -1
//		// Note: rem64 can be negative (e.g. -1 to -7).
//		// If rem64 is negative, we handle it purely with +1 or -1 later,
//		// because we don't have +8 keys.
//		n8 := 0
//		rem8 := rem64
//
//		if rem64 > 0 {
//			n8 = rem64 / 8
//			rem8 = rem64 % 8
//			// Heuristic: If remainder > 4, round up?
//			// e.g. 7 -> 1x(-8) + 1x(+1) (2 hops) vs 7x(-1) (7 hops).
//			if rem8 > 4 {
//				n8++
//				rem8 -= 8
//			}
//		}
//
//		// Step C: Unit steps (+1 or -1)
//		n1 := rem8
//
//		// Execution
//		current := ct
//		// var err error
//		first := true
//
//		apply := func(rots int, step int32) error {
//			for i := 0; i < rots; i++ {
//				next, err := ctx.CC.EvalRotate(current, step)
//				if err != nil {
//					return err
//				}
//				if !first {
//					current.Close()
//				}
//				current = next
//				first = false
//			}
//			return nil
//		}
//
//		// Apply -64s
//		if err := apply(n64, -64); err != nil {
//			return nil, err
//		}
//
//		// Apply -8s
//		if err := apply(n8, -8); err != nil {
//			return nil, err
//		}
//
//		// Apply units
//		if n1 > 0 {
//			if err := apply(n1, -1); err != nil {
//				return nil, err
//			}
//		} else if n1 < 0 {
//			if err := apply(-n1, 1); err != nil {
//				return nil, err
//			}
//		}
//
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		// Case 1: Positive (Extraction) - Use +1
//		if k > 0 {
//			current := ct
//			// var err error
//			for i := 0; i < k; i++ {
//				next, err := ctx.CC.EvalRotate(current, 1)
//				if err != nil {
//					return nil, err
//				}
//				if i > 0 {
//					current.Close()
//				}
//				current = next
//			}
//			return current, nil
//		}
//
//		// Case 2: Negative (Replication) - Use -32 and -1
//		target := -k
//
//		// Greedy decomposition: e.g. 60 -> 1x32 + 28x1
//		n32 := target / 32
//		n1 := target % 32
//
//		// Optimization: If remainder is large (e.g. 31), could overshoot?
//		// But we don't have +1 correction logic easily available for Negatives in this snippet.
//		// 31 hops is acceptable for our budget.
//
//		current := ct
//		// var err error
//		first := true
//
//		apply := func(count int, step int32) error {
//			for i := 0; i < count; i++ {
//				next, err := ctx.CC.EvalRotate(current, step)
//				if err != nil {
//					return err
//				}
//				if !first {
//					current.Close()
//				}
//				current = next
//				first = false
//			}
//			return nil
//		}
//
//		if err := apply(n32, -32); err != nil {
//			return nil, err
//		}
//		if err := apply(n1, -1); err != nil {
//			return nil, err
//		}
//
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		current := ct
//		// var err error
//		first := true
//
//		// Helper to apply a step N times
//		apply := func(count int, step int32) error {
//			for i := 0; i < count; i++ {
//				next, err := ctx.CC.EvalRotate(current, step)
//				if err != nil {
//					return err
//				}
//				if !first {
//					current.Close()
//				}
//				current = next
//				first = false
//			}
//			return nil
//		}
//
//		if k > 0 {
//			// POSITIVE (Extraction): Decompose into {4, 1}
//			// e.g., 23 -> 5x4 + 3x1 (8 hops)
//			n4 := k / 4
//			n1 := k % 4
//			if err := apply(n4, 4); err != nil {
//				return nil, err
//			}
//			if err := apply(n1, 1); err != nil {
//				return nil, err
//			}
//			return current, nil
//		}
//
//		// NEGATIVE (Replication): Decompose into {-256, -64, -16, -4, -1}
//		// e.g., -1024 -> 4x(-256) (4 hops)
//		val := -k
//
//		// Greedy decomposition
//		steps := []int32{-256, -64, -16, -4, -1}
//
//		for _, step := range steps {
//			mag := int(-step) // Magnitude (e.g., 256)
//			count := val / mag
//			val = val % mag
//
//			if count > 0 {
//				if err := apply(count, step); err != nil {
//					return nil, err
//				}
//			}
//		}
//
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		current := ct
//		// var err error
//		first := true
//
//		apply := func(count int, step int32) error {
//			for i := 0; i < count; i++ {
//				next, err := ctx.CC.EvalRotate(current, step)
//				if err != nil {
//					return err
//				}
//				if !first {
//					current.Close()
//				}
//				current = next
//				first = false
//			}
//			return nil
//		}
//
//		// Case 1: Positive (Extraction 0..23) - Use +1
//		if k > 0 {
//			if err := apply(k, 1); err != nil {
//				return nil, err
//			}
//			return current, nil
//		}
//
//		// Case 2: Negative (Replication) - Decompose
//		val := -k
//
//		// Greedy decomposition: 512 -> 64 -> 8 -> 1
//		// This guarantees minimal hops (max ~4 per magnitude)
//		steps := []int32{-512, -64, -8, -1}
//
//		for _, step := range steps {
//			mag := int(-step)
//			count := val / mag
//			val = val % mag
//			if count > 0 {
//				if err := apply(count, step); err != nil {
//					return nil, err
//				}
//			}
//		}
//
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		current := ct
//		// var err error
//		first := true
//
//		apply := func(count int, step int32) error {
//			for i := 0; i < count; i++ {
//				next, err := ctx.CC.EvalRotate(current, step)
//				if err != nil {
//					return err
//				}
//				if !first {
//					current.Close()
//				}
//				current = next
//				first = false
//			}
//			return nil
//		}
//
//		// Extraction (0..23): Use {4, 1}
//		if k > 0 {
//			n4, n1 := k/4, k%4
//			if err := apply(n4, 4); err != nil {
//				return nil, err
//			}
//			if err := apply(n1, 1); err != nil {
//				return nil, err
//			}
//			return current, nil
//		}
//
//		// Replication (Negative): Use {-256, -64, -16, -4, -1}
//		val := -k
//		steps := []int32{-256, -64, -16, -4, -1}
//
//		for _, step := range steps {
//			mag := int(-step)
//			count := val / mag
//			val %= mag
//			if count > 0 {
//				if err := apply(count, step); err != nil {
//					return nil, err
//				}
//			}
//		}
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		current := ct
//		// var err error
//		first := true
//
//		apply := func(count int, step int32) error {
//			for i := 0; i < count; i++ {
//				next, err := ctx.CC.EvalRotate(current, step)
//				if err != nil {
//					return err
//				}
//				if !first {
//					current.Close()
//				}
//				current = next
//				first = false
//			}
//			return nil
//		}
//
//		if k > 0 {
//			// Positive: Use +1
//			if err := apply(k, 1); err != nil {
//				return nil, err
//			}
//			return current, nil
//		}
//
//		// Negative: {-512, -64, -8, -1}
//		val := -k
//		steps := []int32{-512, -64, -8, -1}
//
//		for _, step := range steps {
//			mag := int(-step)
//			count := val / mag
//			val %= mag
//			if count > 0 {
//				if err := apply(count, step); err != nil {
//					return nil, err
//				}
//			}
//		}
//		return current, nil
//	}
//
//	func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
//		if k == 0 {
//			return ct.Clone()
//		}
//
//		current := ct
//		// var err error
//		first := true
//
//		apply := func(count int, step int32) error {
//			for i := 0; i < count; i++ {
//				next, err := ctx.CC.EvalRotate(current, step)
//				if err != nil {
//					return err
//				}
//				if !first {
//					current.Close()
//				}
//				current = next
//				first = false
//			}
//			return nil
//		}
//
//		// Positive: Use +1
//		if k > 0 {
//			if err := apply(k, 1); err != nil {
//				return nil, err
//			}
//			return current, nil
//		}
//
//		// Negative: Use Base-8 {-512, -64, -8, -1}
//		// Max hops: 7 per magnitude, but average is much lower.
//		// Total max hops ~20-25. Safe for 80-bit budget.
//		val := -k
//		steps := []int32{-512, -64, -8, -1}
//
//		for _, step := range steps {
//			mag := int(-step)
//			count := val / mag
//			val %= mag
//			if count > 0 {
//				if err := apply(count, step); err != nil {
//					return nil, err
//				}
//			}
//		}
//		return current, nil
//	}
// func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
// 	if k == 0 {
// 		return ct.Clone()
// 	}
//
// 	current := ct
// 	// var err error
// 	first := true
//
// 	apply := func(count int, step int32) error {
// 		for i := 0; i < count; i++ {
// 			next, err := ctx.CC.EvalRotate(current, step)
// 			if err != nil {
// 				return err
// 			}
// 			if !first {
// 				current.Close()
// 			}
// 			current = next
// 			first = false
// 		}
// 		return nil
// 	}
//
// 	// Extraction (0..23): Use {4, 1}
// 	if k > 0 {
// 		n4, n1 := k/4, k%4
// 		if err := apply(n4, 4); err != nil {
// 			return nil, err
// 		}
// 		if err := apply(n1, 1); err != nil {
// 			return nil, err
// 		}
// 		return current, nil
// 	}
//
// 	// Replication (Negative): Use {-256, -64, -16, -4, -1}
// 	// Greedy decomposition
// 	val := -k
// 	steps := []int32{-256, -64, -16, -4, -1}
//
// 	for _, step := range steps {
// 		mag := int(-step)
// 		count := val / mag
// 		val %= mag
// 		if count > 0 {
// 			if err := apply(count, step); err != nil {
// 				return nil, err
// 			}
// 		}
// 	}
// 	return current, nil
// }

// func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
// 	if k == 0 {
// 		return ct.Clone()
// 	}
//
// 	// Standard Binary Decomposition (1 hop per bit set)
// 	// Since we have all powers of 2, this is very efficient.
//
// 	current := ct
// 	first := true
//
// 	// Handle Negative
// 	// Note: Our loop below handles positive 'shift'. If k is negative, we need to decompose -k
// 	// and use negative keys.
//
// 	isNegative := k < 0
// 	val := k
// 	if isNegative {
// 		val = -k
// 	}
//
// 	for shift := 1; shift <= val; shift *= 2 {
// 		if (val & shift) != 0 {
// 			rotVal := int32(shift)
// 			if isNegative {
// 				rotVal = -rotVal
// 			}
//
// 			next, err := ctx.CC.EvalRotate(current, rotVal)
// 			if err != nil {
// 				return nil, err
// 			}
//
// 			if !first {
// 				current.Close()
// 			}
// 			current = next
// 			first = false
// 		}
// 	}
// 	return current, nil
// }

// func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
// 	if k == 0 {
// 		return ct.Clone()
// 	}
//
// 	// Simple Binary Decomposition
// 	// Works because we have all powers of 2 keys
// 	current := ct
// 	first := true
//
// 	isNeg := k < 0
// 	val := k
// 	if isNeg {
// 		val = -k
// 	}
//
// 	for shift := 1; shift <= val; shift *= 2 {
// 		if (val & shift) != 0 {
// 			rot := int32(shift)
// 			if isNeg {
// 				rot = -rot
// 			}
//
// 			next, err := ctx.CC.EvalRotate(current, rot)
// 			if err != nil {
// 				return nil, err
// 			}
// 			if !first {
// 				current.Close()
// 			}
// 			current = next
// 			first = false
// 		}
// 	}
// 	return current, nil
// }

func (ctx *FHEContext) RotateSparse(ct *openfhe.Ciphertext, k int) (*openfhe.Ciphertext, error) {
	if k == 0 {
		return ct.Clone()
	}

	current := ct
	// var err error
	first := true

	// Helper to apply a specific rotation 'step', 'count' times
	apply := func(count int, step int32) error {
		for i := 0; i < count; i++ {
			next, err := ctx.CC.EvalRotate(current, step)
			if err != nil {
				return err
			}
			if !first {
				current.Close() // Clean up intermediate ciphertext
			}
			current = next
			first = false
		}
		return nil
	}

	// Case 1: Positive (Extraction 0..23) -> Use +1 repeated
	if k > 0 {
		if err := apply(k, 1); err != nil {
			return nil, err
		}
		return current, nil
	}

	// Case 2: Negative (Replication) -> Base-8 Decomposition
	// Decompose into {-512, -64, -8, -1}
	val := -k
	steps := []int32{-512, -64, -8, -1}

	for _, step := range steps {
		mag := int(-step)
		count := val / mag
		val = val % mag

		if count > 0 {
			if err := apply(count, step); err != nil {
				return nil, err
			}
		}
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
