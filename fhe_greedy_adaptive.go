//go:build openfhe

package kbucket

import (
	"github.com/dozyio/openfhe-go/openfhe"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

// GetBucketPIRGreedyAdaptive performs a secure, capacity-adaptive PIR query.
//
// Security: Uses "Destructive Summation" to ensure only 1 bucket is retrievable.
// Capacity: Adapts to large buckets. If a bucket fits in 1 ring (normal), returns 1 CT.
//
//	If a bucket is huge (>32KB), returns 2+ CTs.
func (rt *RoutingTable) GetBucketPIRGreedyAdaptive(queryCt *openfhe.Ciphertext, ps peerstore.Peerstore) ([]*openfhe.Ciphertext, error) {
	if rt.fheCtx == nil {
		return nil, ErrFHENotEnabled
	}

	cc := rt.fheCtx.cc
	ringDim := rt.fheCtx.ringDim
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
			addrs := ps.Addrs(p.Id)
			// Optional: filter addrs here to keep size reasonable
			if len(addrs) > 0 {
				connectable = append(connectable, ConnectablePeer{p.Id, addrs})
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

// extractAndReplicateBit extracts bit at index 0 and replicates it 'count' times.
func (rt *RoutingTable) extractAndReplicateBit(cc *openfhe.CryptoContext, queryWithBitAtZero *openfhe.Ciphertext, count int) (*openfhe.Ciphertext, error) {
	// 1. Mask to isolate bit 0: [b, ?, ?...] -> [b, 0, 0...]
	mask := make([]int64, rt.fheCtx.ringDim)
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
