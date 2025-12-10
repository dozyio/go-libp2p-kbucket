//go:build openfhe

package kbucket

import (
	"errors"
	"fmt"

	"github.com/dozyio/openfhe-go/openfhe"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

// EnableFHE enables FHE-based queries for this routing table.
func (rt *RoutingTable) EnableFHE(ctx *FHEContext) {
	rt.fheCtx = ctx
}

// IsFHEEnabled returns true if FHE is enabled for this routing table.
func (rt *RoutingTable) IsFHEEnabled() bool {
	return rt.fheCtx != nil
}

// GetBucketPIR performs the Private Information Retrieval lookup using 24 ciphertexts.
// It takes the client's query vector and the node's peerstore.
// It returns a single encrypted ciphertext containing the selected bucket's peers.
func (rt *RoutingTable) GetBucketPIR(queryVector []*openfhe.Ciphertext, ps peerstore.Peerstore) (*openfhe.Ciphertext, error) {
	if rt.fheCtx == nil {
		return nil, ErrFHENotEnabled
	}

	if ps == nil {
		return nil, errors.New("peerstore cannot be nil for PIR query")
	}

	if len(queryVector) != MaxCPL {
		return nil, fmt.Errorf("invalid query vector size: got %d, want %d", len(queryVector), MaxCPL)
	}

	cc := rt.fheCtx.CC

	// 1. Initialize Accumulator with Encrypted Zero
	zeroPt, err := cc.MakePackedPlaintext([]int64{0})
	if err != nil {
		return nil, fmt.Errorf("failed to make zero plaintext: %w", err)
	}
	defer zeroPt.Close()

	finalAccumulator, err := cc.EvalMultPlain(queryVector[0], zeroPt)
	if err != nil {
		return nil, fmt.Errorf("failed to init accumulator: %w", err)
	}

	rt.tabLock.RLock()
	defer rt.tabLock.RUnlock()

	// 2. Iterate over physical buckets
	for i, bucket := range rt.buckets {
		if bucket.len() == 0 {
			continue
		}

		var selector *openfhe.Ciphertext
		isSelectorAllocated := false

		if i < len(rt.buckets)-1 {
			// Standard Bucket: Corresponds exactly to CPL 'i'
			if i < len(queryVector) {
				selector = queryVector[i] // This is a reference, DO NOT Close()
			}
		} else {
			// Last Bucket: The "Catch-All"
			// Sum all query bits from 'i' to end of vector
			if i < len(queryVector) {
				selector = queryVector[i] // Start with the base
				for k := i + 1; k < len(queryVector); k++ {
					tempSelector, err := cc.EvalAdd(selector, queryVector[k])
					if err != nil {
						return nil, fmt.Errorf("failed to sum selector for bucket %d: %w", i, err)
					}
					if isSelectorAllocated {
						selector.Close() // Close previous intermediate sum
					}
					selector = tempSelector
					isSelectorAllocated = true
				}
			}
		}
		if selector == nil {
			continue
		}

		// 3. Build connectable peer list
		internalPeers := bucket.peers()
		connectablePeers := make([]ConnectablePeer, 0, len(internalPeers))
		for _, pInfo := range internalPeers {
			addrs := ps.Addrs(pInfo.Id)
			if len(addrs) == 0 {
				continue
			}
			connectablePeers = append(connectablePeers, ConnectablePeer{
				ID:    pInfo.Id,
				Addrs: addrs,
			})
		}

		if len(connectablePeers) == 0 {
			if isSelectorAllocated {
				selector.Close()
			}
			continue
		}

		// 4. Serialize bucket data
		serializedData, err := SerializeConnectablePeers(connectablePeers)
		if err != nil {
			rt.logError("failed to serialize connectable peers: %v", err)
			if isSelectorAllocated {
				selector.Close()
			}
			continue
		}

		dataPt, err := cc.MakePackedPlaintext(serializedData)
		if err != nil {
			rt.logError("failed to make packed plaintext for bucket %d: %v", i, err)
			if isSelectorAllocated {
				selector.Close()
			}
			continue
		}

		// 5. Homomorphic Multiplication: Selector * Data
		maskedData, err := cc.EvalMultPlain(selector, dataPt)
		dataPt.Close()
		if isSelectorAllocated {
			selector.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("EvalMultPlain bucket %d: %w", i, err)
		}

		// 6. Accumulate
		tempAccumulator, err := cc.EvalAdd(finalAccumulator, maskedData)
		if err != nil {
			maskedData.Close()
			return nil, fmt.Errorf("EvalAdd bucket %d: %w", i, err)
		}

		finalAccumulator.Close()
		maskedData.Close()
		finalAccumulator = tempAccumulator
	}

	return finalAccumulator, nil
}

// GetBucketPIRPacked performs PIR with a single packed ciphertext query (optimized version).
// This uses one ciphertext with SIMD slots instead of 24 separate ciphertexts.
// Requires rotation keys generated via GenerateKeysWithRotation().
//
// Algorithm for each bucket i:
// 1. Rotate query ciphertext by -i positions to move slot[i] to slot[0]
// 2. Extract slot[0] and replicate its value to all slots (via rotation+addition)
// 3. Multiply replicated selector by bucket data (all slots multiplied by same value)
// 4. Accumulate into final result
func (rt *RoutingTable) GetBucketPIRPacked(queryCt *openfhe.Ciphertext, ps peerstore.Peerstore) (*openfhe.Ciphertext, error) {
	if rt.fheCtx == nil {
		return nil, ErrFHENotEnabled
	}

	if ps == nil {
		return nil, errors.New("peerstore cannot be nil for PIR query")
	}

	cc := rt.fheCtx.CC

	// Initialize accumulator
	zeroPt, err := cc.MakePackedPlaintext([]int64{0})
	if err != nil {
		return nil, fmt.Errorf("failed to make zero plaintext: %w", err)
	}
	defer zeroPt.Close()

	finalAccumulator, err := cc.EvalMultPlain(queryCt, zeroPt)
	if err != nil {
		return nil, fmt.Errorf("failed to init accumulator: %w", err)
	}

	rt.tabLock.RLock()
	defer rt.tabLock.RUnlock()

	// Process each bucket
	for i, bucket := range rt.buckets {
		if bucket.len() == 0 {
			continue
		}

		// Build connectable peer list
		internalPeers := bucket.peers()
		connectablePeers := make([]ConnectablePeer, 0, len(internalPeers))
		for _, pInfo := range internalPeers {
			addrs := ps.Addrs(pInfo.Id)
			if len(addrs) == 0 {
				continue
			}
			connectablePeers = append(connectablePeers, ConnectablePeer{
				ID:    pInfo.Id,
				Addrs: addrs,
			})
		}

		if len(connectablePeers) == 0 {
			continue
		}

		// Serialize bucket data
		serializedData, err := SerializeConnectablePeers(connectablePeers)
		if err != nil {
			rt.logError("failed to serialize connectable peers: %v", err)
			continue
		}

		// Step 1: Extract the selector for this bucket
		// For standard buckets: extract slot[i]
		// For catch-all bucket: sum slots [i..MaxCPL-1]
		var selector *openfhe.Ciphertext
		if i < len(rt.buckets)-1 {
			// Standard bucket: extract slot[i] to slot[0]
			selector, err = rt.extractSlot(cc, queryCt, i)
			if err != nil {
				return nil, fmt.Errorf("failed to extract slot %d: %w", i, err)
			}
		} else {
			// Catch-all bucket: sum all slots from i to MaxCPL-1
			// This handles queries for any CPL >= i
			selector, err = rt.extractAndSumSlots(cc, queryCt, i, MaxCPL)
			if err != nil {
				return nil, fmt.Errorf("failed to extract catch-all slots: %w", err)
			}
		}

		// Step 2: Replicate selector to cover all data slots
		// This is the KEY: we need the same selector value at ALL positions where we have data
		replicatedSelector, err := rt.replicateSlotZero(cc, selector, len(serializedData))
		selector.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to replicate selector for bucket %d: %w", i, err)
		}

		// Step 3: Create plaintext with data starting at slot[0]
		// Since we've replicated the selector to all positions, we can now put data at slot[0..]
		plaintextVector := make([]int64, rt.fheCtx.ringDim)
		for j := 0; j < len(serializedData) && j < rt.fheCtx.ringDim; j++ {
			plaintextVector[j] = serializedData[j]
		}

		dataPt, err := cc.MakePackedPlaintext(plaintextVector)
		if err != nil {
			replicatedSelector.Close()
			rt.logError("failed to make packed plaintext for bucket %d: %v", i, err)
			continue
		}

		// Step 4: Multiply replicated selector by data
		// Now all data bytes get multiplied by the same selector value (0 or 1)
		maskedData, err := cc.EvalMultPlain(replicatedSelector, dataPt)
		replicatedSelector.Close()
		dataPt.Close()
		if err != nil {
			return nil, fmt.Errorf("EvalMultPlain bucket %d: %w", i, err)
		}

		// Step 5: Accumulate into final result
		tempAccumulator, err := cc.EvalAdd(finalAccumulator, maskedData)
		if err != nil {
			maskedData.Close()
			return nil, fmt.Errorf("EvalAdd bucket %d: %w", i, err)
		}

		finalAccumulator.Close()
		maskedData.Close()
		finalAccumulator = tempAccumulator
	}

	return finalAccumulator, nil
}

// extractSlot extracts slot i from the ciphertext, leaving it in slot[0] with all other slots zeroed.
func (rt *RoutingTable) extractSlot(cc *openfhe.CryptoContext, ct *openfhe.Ciphertext, slotIndex int) (*openfhe.Ciphertext, error) {
	// Step 1: Rotate so slot[slotIndex] moves to slot[0]
	// EvalRotate with positive index rotates LEFT, so we use +slotIndex to move slot[slotIndex] to slot[0]
	rotated, err := cc.EvalRotate(ct, int32(slotIndex))
	if err != nil {
		return nil, fmt.Errorf("rotation failed: %w", err)
	}

	// Step 2: Mask to keep only slot[0], zero out all others
	maskVector := make([]int64, rt.fheCtx.ringDim)
	maskVector[0] = 1
	maskPt, err := cc.MakePackedPlaintext(maskVector)
	if err != nil {
		rotated.Close()
		return nil, fmt.Errorf("failed to create mask: %w", err)
	}

	extracted, err := cc.EvalMultPlain(rotated, maskPt)
	maskPt.Close()
	rotated.Close()
	if err != nil {
		return nil, fmt.Errorf("mask multiplication failed: %w", err)
	}

	return extracted, nil
}

// replicateSlotZero takes a ciphertext with a value in slot[0] and replicates it to cover dataSize slots.
// Uses a doubling strategy with rotation+addition, but STOPS appropriately to avoid wraparound.
// This is the KEY FIX: we only replicate as much as needed for the data, not the entire ringDim.
func (rt *RoutingTable) replicateSlotZero(cc *openfhe.CryptoContext, ct *openfhe.Ciphertext, dataSize int) (*openfhe.Ciphertext, error) {
	replicated := ct

	// Find the next power of 2 >= dataSize to ensure full coverage
	targetSize := 1
	for targetSize < dataSize {
		targetSize *= 2
	}

	// Replicate using doubling: -1, -2, -4, -8, -16, ... (rotate RIGHT to replicate)
	// Stop when the NEXT shift would exceed targetSize
	numIterations := 0
	for shift := int32(1); int(shift) < targetSize; shift *= 2 {
		// Rotate RIGHT by shift positions (negative index)
		shifted, err := cc.EvalRotate(replicated, -shift)
		if err != nil {
			if numIterations > 0 {
				replicated.Close()
			}
			return nil, fmt.Errorf("replication rotation failed at shift %d: %w", shift, err)
		}

		// Add shifted version to replicated
		temp, err := cc.EvalAdd(replicated, shifted)
		shifted.Close()
		if err != nil {
			if numIterations > 0 {
				replicated.Close()
			}
			return nil, fmt.Errorf("replication addition failed at shift %d: %w", shift, err)
		}

		if numIterations > 0 {
			replicated.Close()
		}
		replicated = temp
		numIterations++
	}

	return replicated, nil
}

// extractAndSumSlots extracts and sums slots from startIdx to endIdx (exclusive).
// Used for the catch-all bucket which needs to sum multiple query slots.
// Returns a ciphertext with the sum in slot[0], all other slots zero.
func (rt *RoutingTable) extractAndSumSlots(cc *openfhe.CryptoContext, ct *openfhe.Ciphertext, startIdx, endIdx int) (*openfhe.Ciphertext, error) {
	var accumulator *openfhe.Ciphertext

	for i := startIdx; i < endIdx; i++ {
		// Extract slot i (will be in slot[0])
		extracted, err := rt.extractSlot(cc, ct, i)
		if err != nil {
			if accumulator != nil {
				accumulator.Close()
			}
			return nil, fmt.Errorf("failed to extract slot %d: %w", i, err)
		}

		if accumulator == nil {
			accumulator = extracted
		} else {
			// Add to accumulator
			temp, err := cc.EvalAdd(accumulator, extracted)
			extracted.Close()
			if err != nil {
				accumulator.Close()
				return nil, fmt.Errorf("failed to sum slot %d: %w", i, err)
			}
			accumulator.Close()
			accumulator = temp
		}
	}

	return accumulator, nil
}

func (rt *RoutingTable) logError(msg string, args ...interface{}) {
	fmt.Printf("ERROR: "+msg+"\n", args...)
}
