//go:build openfhe

package kbucket

import (
	"fmt"

	"github.com/dozyio/openfhe-go/openfhe"
)

// Deprecated: Use GetBucket() with PIRStrategyGreedyAdaptive instead.
// This method will be removed in v2.0.
//
// GetBucketPIRGreedyAdaptive performs a secure, capacity-adaptive PIR query.
//
// Security: Uses "Destructive Summation" to ensure only 1 bucket is retrievable.
// Capacity: Adapts to large buckets. If a bucket fits in 1 ring (normal), returns 1 CT.
//
//	If a bucket is huge (>32KB), returns 2+ CTs.
func (rt *RoutingTable) GetBucketPIRGreedyAdaptive(queryCt *openfhe.Ciphertext) ([]*openfhe.Ciphertext, error) {
	fheCtx := rt.GetFHEContext()
	if fheCtx == nil {
		return nil, ErrFHENotEnabled
	}

	cc := fheCtx.CC
	ringDim := fheCtx.ringDim
	bytesPerRing := ringDim * 2 // Dense packing (2 bytes/slot)

	// 1. Pre-Calculate Max Size needed
	// We need to know the maximum number of rings required by ANY bucket.
	// (In PIR, all responses must be the same size to avoid leaking which bucket was picked).
	maxBytes := 0

	// Temporary cache for serialized buckets to avoid re-doing work
	serializedBuckets := make(map[int][]int64)

	rt.tabLock.RLock()
	for i, bucket := range rt.buckets {
		if i >= MaxCPL {
			break
		}
		peers := bucket.peers()
		if len(peers) == 0 {
			continue
		}

		connectable := make([]ConnectablePeer, 0, len(peers))
		for _, p := range peers {
			if len(p.Addrs) > 0 {
				connectable = append(connectable, ConnectablePeer{p.Id, p.Addrs})
			}
		}
		if len(connectable) == 0 {
			continue
		}

		// Dense Serialize
		packed, err := SerializeConnectablePeersDense(connectable)
		if err != nil {
			continue
		}

		serializedBuckets[i] = packed

		// Track max size (in bytes)
		sizeInBytes := len(packed) * 2
		if sizeInBytes > maxBytes {
			maxBytes = sizeInBytes
		}
	}
	rt.tabLock.RUnlock()

	// Calculate how many rings we need to return
	// Normally this will be 1. If data > 32KB, it becomes 2.
	numRings := (maxBytes + bytesPerRing - 1) / bytesPerRing
	if numRings == 0 {
		numRings = 1 // Always return at least 1
	}

	responses := make([]*openfhe.Ciphertext, numRings)

	// 2. Build the Response Rings
	for r := 0; r < numRings; r++ {

		// Init Accumulator for this ring
		zeroPt, _ := cc.MakePackedPlaintext([]int64{0})
		acc, _ := cc.EvalMultPlain(queryCt, zeroPt) // Encrypted Zero with noise
		zeroPt.Close()

		// Summation Loop (The Greedy Proof)
		for i, packedData := range serializedBuckets {
			// Calculate which slice of this bucket belongs in Ring 'r'
			// Slots per ring = ringDim
			startSlot := r * ringDim
			endSlot := startSlot + ringDim

			if startSlot >= len(packedData) {
				continue
			}

			// Get chunk
			limit := endSlot
			if limit > len(packedData) {
				limit = len(packedData)
			}
			chunk := packedData[startSlot:limit]

			// Pad chunk to ringDim size
			if len(chunk) < ringDim {
				padded := make([]int64, ringDim)
				copy(padded, chunk)
				chunk = padded
			}

			// A. Create Plaintext for this chunk
			pt, err := cc.MakePackedPlaintext(chunk)
			if err != nil {
				continue
			}

			// B. Extract Selector Bit 'i' from Query
			// We rotate the query so bit 'i' moves to pos 0
			rotatedQuery, err := cc.EvalRotate(queryCt, int32(i))
			if err != nil {
				pt.Close()
				continue
			}

			// C. Replicate Selector to cover this chunk
			// We need a mask of [1,1,1...] matching ringDim
			selector, err := rt.extractAndReplicateBit(cc, rotatedQuery, ringDim)
			rotatedQuery.Close()
			if err != nil {
				pt.Close()
				continue
			}

			// D. Multiply: Selector * Chunk
			maskedChunk, err := cc.EvalMultPlain(selector, pt)
			selector.Close()
			pt.Close()
			if err != nil {
				continue
			}

			// E. Add to Accumulator
			nextAcc, err := cc.EvalAdd(acc, maskedChunk)
			maskedChunk.Close()
			if err != nil {
				continue
			}

			acc.Close()
			acc = nextAcc
		}
		responses[r] = acc
	}

	return responses, nil
}

// GetBucketPIRGreedyAdaptiveNormalized performs a secure, capacity-adaptive PIR query.
//
// Security: Uses "Destructive Summation" to ensure only 1 bucket is retrievable.
// Privacy: Uses GetNormalizedPeers (Peer2PIR) to ensure every query returns k peers,
//
//	hiding the actual bucket occupancy and structure.
//
// Capacity: Adapts to large buckets. If a bucket fits in 1 ring (normal), returns 1 CT.
//
//	If a bucket is huge (>32KB), returns 2+ CTs.
//
// Deprecated: Use GetBucket() with PIRStrategyGreedyNormalized instead.
// This method will be removed in v2.0.
func (rt *RoutingTable) GetBucketPIRGreedyAdaptiveNormalized(queryCt *openfhe.Ciphertext, kp *openfhe.KeyPair) ([]*openfhe.Ciphertext, error) {
	fheCtx := rt.GetFHEContext()
	if fheCtx == nil {
		return nil, ErrFHENotEnabled
	}

	cc := fheCtx.CC
	ringDim := fheCtx.ringDim
	bytesPerRing := ringDim * 2 // Dense packing (2 bytes/slot)

	// 1. Pre-Calculate Max Size needed
	// We need to know the maximum number of rings required by ANY bucket.
	// (In PIR, all responses must be the same size to avoid leaking which bucket was picked).
	maxBytes := 0

	// Temporary cache for serialized buckets to avoid re-doing work
	serializedBuckets := make(map[int][]int64)

	// NOTE: We do NOT hold rt.tabLock here because GetNormalizedPeers acquires its own Read Lock.
	// Iterating 0..MaxCPL ensures we cover the entire potential privacy space.
	for cpl := 0; cpl < MaxCPL; cpl++ {
		if cpl >= len(rt.buckets) {
			fmt.Printf("CPL %d out of range (Table size: %d). Stopping PIR processing.", cpl, len(rt.buckets))
			break
		}
		// Peer2PIR Integration:
		// Instead of grabbing the raw bucket, we ask for the Normalized view for this CPL.
		// This fills empty/sparse buckets with peers from closer/farther buckets
		peers := rt.GetNormalizedPeers(uint(cpl))

		if len(peers) == 0 {
			continue
		}

		connectable := make([]ConnectablePeer, 0, len(peers))
		for _, pid := range peers {
			// Look up peer info to get addresses
			bucketID := rt.bucketIdForPeer(pid)
			bucket := rt.buckets[bucketID]
			peerInfo := bucket.getPeer(pid)

			if peerInfo != nil && len(peerInfo.Addrs) > 0 {
				connectable = append(connectable, ConnectablePeer{pid, peerInfo.Addrs})
			}
		}

		if len(connectable) == 0 {
			continue
		}

		// Dense Serialize
		packed, err := SerializeConnectablePeersDense(connectable)
		if err != nil {
			continue
		}

		serializedBuckets[cpl] = packed

		// Track max size (in bytes)
		sizeInBytes := len(packed) * 2
		if sizeInBytes > maxBytes {
			maxBytes = sizeInBytes
		}
	}

	// Calculate how many rings we need to return
	// Normally this will be 1. If data > 32KB, it becomes 2.
	numRings := (maxBytes + bytesPerRing - 1) / bytesPerRing
	if numRings == 0 {
		numRings = 1 // Always return at least 1
	}

	responses := make([]*openfhe.Ciphertext, numRings)

	// 2. Build the Response Rings
	for r := 0; r < numRings; r++ {

		// Init Accumulator for this ring
		zeroPt, _ := cc.MakePackedPlaintext([]int64{0})
		acc, _ := cc.EvalMultPlain(queryCt, zeroPt) // Encrypted Zero with noise
		zeroPt.Close()

		// NEW: Calculate how many slots we actually need to cover
		// Each slot holds 2 bytes (dense packing)
		neededSlots := (maxBytes + 1) / 2
		if neededSlots < 1 {
			neededSlots = 1
		}

		// Round up to next power of 2 for the doubling algorithm
		replicationLimit := 1
		for replicationLimit < neededSlots {
			replicationLimit *= 2
		}
		// Cap at RingDim
		if replicationLimit > ringDim {
			replicationLimit = ringDim
		}

		// Summation Loop (The Greedy Proof)
		for i, packedData := range serializedBuckets {
			// Calculate which slice of this bucket belongs in Ring 'r'
			// Slots per ring = ringDim
			startSlot := r * ringDim
			endSlot := startSlot + ringDim

			if startSlot >= len(packedData) {
				continue
			}

			// Get chunk
			limit := endSlot
			if limit > len(packedData) {
				limit = len(packedData)
			}
			chunk := packedData[startSlot:limit]

			// Pad chunk to ringDim size
			if len(chunk) < ringDim {
				padded := make([]int64, ringDim)
				copy(padded, chunk)
				chunk = padded
			}

			// A. Create Plaintext for this chunk
			pt, err := cc.MakePackedPlaintext(chunk)
			if err != nil {
				continue
			}

			// B. Extract Selector Bit 'i' from Query
			// We rotate the query so bit 'i' moves to pos 0

			// naive key rotations
			// rotatedQuery, err := cc.EvalRotate(queryCt, int32(i))
			// power-of-two rotations
			// rotatedQuery, err := fheCtx.RotateComposite(queryCt, i)
			// single unit rotations
			// rotatedQuery, err := fheCtx.RotateIterative(queryCt, i)
			// sparse rotation
			rotatedQuery, err := fheCtx.RotateSparse(queryCt, i)
			if err != nil {
				pt.Close()
				continue
			}
			rt.DebugProbe(fmt.Sprintf("Step B (Extract CPL %d)", i), rotatedQuery, kp)

			// C. Replicate Selector to cover this chunk
			// We need a mask of [1,1,1...] matching ringDim

			// standard extract
			// selector, err := rt.extractAndReplicateBit(cc, rotatedQuery, ringDim)

			// single unit extract
			// selector, err := rt.extractAndReplicateBitIterative(cc, rotatedQuery, ringDim)

			// You need a specific helper for replication too, using RotateSparse internally
			// selector, err := rt.extractAndReplicateBitSparse(cc, rotatedQuery, ringDim)
			selector, err := rt.extractAndReplicateBitSparse(cc, rotatedQuery, replicationLimit)

			rotatedQuery.Close()
			if err != nil {
				pt.Close()
				continue
			}
			rt.DebugProbe(fmt.Sprintf("Step C (Replicate CPL %d)", i), selector, kp)

			// D. Multiply: Selector * Chunk
			maskedChunk, err := cc.EvalMultPlain(selector, pt)
			selector.Close()
			pt.Close()
			if err != nil {
				continue
			}
			rt.DebugProbe(fmt.Sprintf("Step D (Mult CPL %d)", i), maskedChunk, kp)

			// E. Add to Accumulator
			nextAcc, err := cc.EvalAdd(acc, maskedChunk)
			maskedChunk.Close()
			if err != nil {
				continue
			}
			rt.DebugProbe(fmt.Sprintf("Step E (Acc CPL %d)", i), acc, kp)

			acc.Close()
			acc = nextAcc
		}
		responses[r] = acc
	}

	return responses, nil
}

// extractAndReplicateBit extracts bit at index 0 and replicates it 'count' times.
func (rt *RoutingTable) extractAndReplicateBit(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, count int) (*openfhe.Ciphertext, error) {
	// 1. Mask to isolate bit 0: [b, ?, ?...] -> [b, 0, 0...]
	ringDim := int(cc.GetRingDimension())
	mask := make([]int64, ringDim)
	mask[0] = 1
	maskPt, _ := cc.MakePackedPlaintext(mask)

	bitOnly, err := cc.EvalMultPlain(queryWithBitAtZero, maskPt)
	maskPt.Close()
	if err != nil {
		return nil, err
	}

	// 2. Replicate using doubling
	current := bitOnly
	for size := 1; size < count; size *= 2 {
		// Rotate right (negative) to copy forward
		rotated, err := cc.EvalRotate(current, int32(-size))
		if err != nil {
			if current != bitOnly {
				current.Close()
			}
			return nil, err
		}

		summed, err := cc.EvalAdd(current, rotated)
		rotated.Close()
		if err != nil {
			if current != bitOnly {
				current.Close()
			}
			return nil, err
		}

		if current != bitOnly {
			current.Close() // Close intermediate results
		}
		current = summed
	}

	return current, nil
}

// extractAndReplicateBitIterative performs replication using only the -1 key.
func (rt *RoutingTable) extractAndReplicateBitIterative(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, count int) (*openfhe.Ciphertext, error) {
	fheCtx := rt.GetFHEContext()
	if fheCtx == nil {
		return nil, ErrFHENotEnabled
	}

	// 1. Mask to isolate bit 0
	ringDim := int(cc.GetRingDimension())
	mask := make([]int64, ringDim)
	mask[0] = 1
	maskPt, _ := cc.MakePackedPlaintext(mask)

	current, err := cc.EvalMultPlain(queryWithBitAtZero, maskPt)
	maskPt.Close()
	if err != nil {
		return nil, err
	}

	// 2. Replicate using doubling algorithm, but shifting iteratively
	// We still use the "doubling" strategy (1->2->4->8), but the *shift* itself
	// is done by calling RotateIterative(size).
	for size := 1; size < count; size *= 2 {
		// Rotate right by 'size' (using -1 key iteratively)
		rotated, err := fheCtx.RotateIterative(current, -size)
		if err != nil {
			if size > 1 {
				current.Close()
			}
			return nil, err
		}

		// Add: current + rotated
		summed, err := cc.EvalAdd(current, rotated)
		rotated.Close()
		if err != nil {
			if size > 1 {
				current.Close()
			}
			return nil, err
		}

		if size > 1 {
			current.Close()
		}
		current = summed
	}

	return current, nil
}

// extractAndReplicateBitSparse performs the "smearing" operation to copy the bit at index 0
// to all other slots, using only the sparse key set {1, 5, -1, -5}.
//
//	func (rt *RoutingTable) extractAndReplicateBitSparse(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, count int) (*openfhe.Ciphertext, error) {
//		// 1. Mask to isolate the single bit at index 0
//		// Transformation: [b, ?, ?...] -> [b, 0, 0...]
//		mask := make([]int64, fheCtx.ringDim)
//		mask[0] = 1
//		maskPt, _ := cc.MakePackedPlaintext(mask)
//
//		current, err := cc.EvalMultPlain(queryWithBitAtZero, maskPt)
//		maskPt.Close() // Clean up plaintext
//		if err != nil {
//			return nil, err
//		}
//
//		// 2. Replicate using the "Doubling" algorithm
//		// We iteratively expand the mask: 1->2, 2->4, 4->8...
//		// We use RotateSparse because we lack dedicated keys for shifts like -2, -4, -8.
//		for size := 1; size < count; size *= 2 {
//			// Calculate the rotation: we need to shift RIGHT by 'size'.
//			// RotateSparse will break this large shift down into steps of -5 and -1.
//			rotated, err := fheCtx.RotateSparse(current, -size)
//			if err != nil {
//				// If rotation fails, clean up the accumulator
//				if size > 1 {
//					current.Close()
//				}
//				return nil, err
//			}
//
//			// Sum the current mask with its shifted copy
//			// [b, b, 0...] + [0, 0, b, b...] -> [b, b, b, b...]
//			summed, err := cc.EvalAdd(current, rotated)
//
//			// Clean up the temporary rotated ciphertext
//			rotated.Close()
//
//			if err != nil {
//				if size > 1 {
//					current.Close()
//				}
//				return nil, err
//			}
//
//			// Update 'current' to the new doubled mask
//			if size > 1 {
//				current.Close() // Free the old 'current' (unless it was the first loop's input)
//			}
//			current = summed
//		}
//
//		return current, nil
//	}
//
//	func (rt *RoutingTable) extractAndReplicateBitSparse(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, limit int) (*openfhe.Ciphertext, error) {
//		// 1. Mask (Same as before)
//		mask := make([]int64, fheCtx.ringDim)
//		mask[0] = 1
//		maskPt, _ := cc.MakePackedPlaintext(mask)
//		current, _ := cc.EvalMultPlain(queryWithBitAtZero, maskPt)
//		maskPt.Close()
//
//		// 2. Replicate ONLY up to 'limit'
//		for size := 1; size < limit; size *= 2 {
//			// Use RotateSparse to handle the shift (using -1 and -64 keys)
//			rotated, err := fheCtx.RotateSparse(current, -size)
//			if err != nil {
//				return nil, err
//			}
//
//			summed, err := cc.EvalAdd(current, rotated)
//			rotated.Close()
//
//			if size > 1 {
//				current.Close()
//			}
//			current = summed
//
//			if err != nil {
//				return nil, err
//			}
//		}
//		return current, nil
//	}
//
//	func (rt *RoutingTable) extractAndReplicateBitSparse(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, limit int) (*openfhe.Ciphertext, error) {
//		// 1. Mask
//		mask := make([]int64, fheCtx.ringDim)
//		mask[0] = 1
//		maskPt, _ := cc.MakePackedPlaintext(mask)
//		current, _ := cc.EvalMultPlain(queryWithBitAtZero, maskPt)
//		maskPt.Close()
//
//		// 2. Replicate
//		// Since we have keys for -1, -2, -4... we can just do 1 hop per loop!
//		for size := 1; size < limit; size *= 2 {
//			rotated, err := cc.EvalRotate(current, int32(-size)) // Direct call possible now!
//			if err != nil {
//				return nil, err
//			}
//
//			summed, err := cc.EvalAdd(current, rotated)
//			rotated.Close()
//			if size > 1 {
//				current.Close()
//			}
//			current = summed
//		}
//		return current, nil
//	}
//
//	func (rt *RoutingTable) extractAndReplicateBitSparse(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, limit int) (*openfhe.Ciphertext, error) {
//		mask := make([]int64, fheCtx.ringDim)
//		mask[0] = 1
//		maskPt, _ := cc.MakePackedPlaintext(mask)
//		current, _ := cc.EvalMultPlain(queryWithBitAtZero, maskPt)
//		maskPt.Close()
//
//		for size := 1; size < limit; size *= 2 {
//			// Direct Rotation (1 Hop)
//			rotated, err := cc.EvalRotate(current, int32(-size))
//			if err != nil {
//				return nil, err
//			}
//
//			summed, err := cc.EvalAdd(current, rotated)
//			if err != nil {
//				rotated.Close()
//				return nil, err
//			}
//
//			rotated.Close()
//			if size > 1 {
//				current.Close()
//			}
//			current = summed
//		}
//		return current, nil
//	}
func (rt *RoutingTable) extractAndReplicateBitSparse(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, limit int) (*openfhe.Ciphertext, error) {
	fheCtx := rt.GetFHEContext()
	if fheCtx == nil {
		return nil, ErrFHENotEnabled
	}

	// 1. Mask
	ringDim := int(cc.GetRingDimension())
	mask := make([]int64, ringDim)
	mask[0] = 1
	maskPt, _ := cc.MakePackedPlaintext(mask)
	current, _ := cc.EvalMultPlain(queryWithBitAtZero, maskPt)
	maskPt.Close()

	// 2. Replicate (Doubling)
	// RotateSparse handles the shifts (e.g., -512 is 1 hop, -1024 is 2 hops)
	for size := 1; size < limit; size *= 2 {
		rotated, err := fheCtx.RotateSparse(current, -size)
		if err != nil {
			if size > 1 {
				current.Close()
			}
			return nil, err
		}

		summed, err := cc.EvalAdd(current, rotated)
		rotated.Close()

		if size > 1 {
			current.Close()
		}
		current = summed
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (rt *RoutingTable) DebugProbe(name string, ct *openfhe.Ciphertext, kp *openfhe.KeyPair) {
	if kp == nil {
		return
	} // Skip if not provided

	fheCtx := rt.GetFHEContext()
	if fheCtx == nil {
		return
	}

	// Decrypt
	pt, err := fheCtx.CC.Decrypt(kp, ct)
	if err != nil {
		fmt.Printf("❌ [DEBUG] %s: DECRYPTION FAILED (Noise > Budget)\n", name)
		return
	}

	// Unpack and print first 8 slots
	vals, _ := pt.GetPackedValue()
	if len(vals) > 8 {
		vals = vals[:8]
	}
	fmt.Printf("✅ [DEBUG] %s: %v ...\n", name, vals)
}
