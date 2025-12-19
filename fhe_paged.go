//go:build openfhe

package kbucket

import (
	"errors"
	"fmt"
	"math"

	"github.com/dozyio/openfhe-go/openfhe"
)

// DefaultBucketStride defines the default stride for Paged PIR when not specified in PIRConfig.
// A stride of 8192 slots allows for ~8KB of data per bucket.
// With realistic multiaddrs (~1-2KB per peer), this supports 4-8 peers per bucket.
// With ringDim=8192, this gives 1 bucket per plaintext = 24 ciphertexts total.
// For better compression, use ringDim=16384 to get 2 buckets per plaintext = 12 ciphertexts.
//
// Note: This is now configurable via PIRConfig.BucketStride. Use CalculateOptimalStride()
// for automatic selection based on ring dimension.
const DefaultBucketStride = 8192

// Deprecated: Use DefaultBucketStride or configure via PIRConfig.BucketStride instead.
const BucketStride = DefaultBucketStride

// GetBucketPIRPaged performs PIR using the "Paged" strategy (Spatial Packing).
// It balances upload size and server performance by packing multiple buckets into
// single plaintexts, reducing the query vector size significantly compared to
// the standard 24-ciphertext approach, without the high CPU cost of the Packed approach.
//
// Algorithm:
// 1. Divide ring dimension into fixed-size strides (e.g., 4096 slots per bucket)
// 2. Pack multiple buckets (e.g., 2-4) into each plaintext at different offsets
// 3. Client sends one-hot vector selecting the PAGE containing target bucket
// 4. Server multiplies and accumulates (no rotations needed!)
// 5. Client extracts data from the correct offset in the response
//
// Deprecated: Use GetBucket() with PIRStrategyPaged instead.
// This method will be removed in v2.0.
func (rt *RoutingTable) GetBucketPIRPaged(queryVector []*openfhe.Ciphertext) (*openfhe.Ciphertext, error) {
	fheCtx := rt.GetFHEContext()
	if fheCtx == nil {
		return nil, ErrFHENotEnabled
	}
	cc := fheCtx.CC
	ringDim := fheCtx.ringDim

	if ringDim < BucketStride {
		return nil, fmt.Errorf("ring dimension %d is too small for bucket stride %d", ringDim, BucketStride)
	}

	bucketsPerPage := ringDim / BucketStride
	numPages := int(math.Ceil(float64(MaxCPL) / float64(bucketsPerPage)))

	if len(queryVector) != numPages {
		return nil, fmt.Errorf("invalid query vector size: got %d, want %d pages", len(queryVector), numPages)
	}

	// 1. Initialize Accumulator
	zeroPt, err := cc.MakePackedPlaintext([]int64{0})
	if err != nil {
		return nil, err
	}
	defer zeroPt.Close()

	finalAccumulator, err := cc.EvalMultPlain(queryVector[0], zeroPt)
	if err != nil {
		return nil, fmt.Errorf("failed to init accumulator: %w", err)
	}

	rt.tabLock.RLock()
	defer rt.tabLock.RUnlock()

	// 2. Iterate over Pages (NOT individual buckets)
	// Each page contains multiple buckets packed at different slot offsets
	for pageIdx := 0; pageIdx < numPages; pageIdx++ {
		pageVector := make([]int64, ringDim)
		pageHasData := false

		// Fill the vector for this page with multiple buckets
		startCPL := pageIdx * bucketsPerPage
		endCPL := startCPL + bucketsPerPage

		for cpl := startCPL; cpl < endCPL && cpl < MaxCPL; cpl++ {
			// Determine which physical bucket corresponds to this logical CPL
			bucketIdx := cpl
			if bucketIdx >= len(rt.buckets) {
				bucketIdx = len(rt.buckets) - 1 // Catch-all bucket
			}

			bucket := rt.buckets[bucketIdx]
			if bucket.len() == 0 {
				continue
			}

			// Retrieve and serialize peers
			connectablePeers := make([]ConnectablePeer, 0, bucket.len())
			for _, pInfo := range bucket.peers() {
				if len(pInfo.Addrs) > 0 {
					connectablePeers = append(connectablePeers, ConnectablePeer{ID: pInfo.Id, Addrs: pInfo.Addrs})
				}
			}

			if len(connectablePeers) == 0 {
				continue
			}

			serialized, err := SerializeConnectablePeers(connectablePeers)
			if err != nil {
				rt.logError("failed to serialize bucket %d: %v", bucketIdx, err)
				continue
			}

			if len(serialized) > BucketStride {
				// Truncate if exceeds stride (safeguard)
				serialized = serialized[:BucketStride]
			}

			// Copy data into the correct offset for this CPL within the page
			// Each bucket gets its own "stride" of slots
			offset := (cpl % bucketsPerPage) * BucketStride
			for k, v := range serialized {
				if offset+k < len(pageVector) {
					pageVector[offset+k] = v
				}
			}
			pageHasData = true
		}

		// If this page is empty, skip multiplication
		if !pageHasData {
			continue
		}

		// 3. Create plaintext and multiply by query selector
		pt, err := cc.MakePackedPlaintext(pageVector)
		if err != nil {
			return nil, err
		}

		maskedPage, err := cc.EvalMultPlain(queryVector[pageIdx], pt)
		pt.Close()
		if err != nil {
			return nil, err
		}

		// 4. Accumulate
		tempAccumulator, err := cc.EvalAdd(finalAccumulator, maskedPage)
		maskedPage.Close()
		if err != nil {
			return nil, err
		}
		finalAccumulator.Close()
		finalAccumulator = tempAccumulator
	}

	return finalAccumulator, nil
}

// CreateQueryVectorPaged generates a query for the Paged PIR strategy.
// It creates a one-hot vector for the PAGE containing the target CPL, not the CPL itself.
// This significantly reduces the query size (e.g., 6 CTs instead of 24).
func (ctx *FHEContext) CreateQueryVectorPaged(cpl int) ([]*openfhe.Ciphertext, error) {
	if cpl < 0 {
		cpl = 0
	}
	if cpl >= MaxCPL {
		cpl = MaxCPL - 1
	}

	bucketsPerPage := ctx.ringDim / BucketStride
	if bucketsPerPage == 0 {
		return nil, errors.New("BucketStride is larger than ring dimension")
	}

	numPages := int(math.Ceil(float64(MaxCPL) / float64(bucketsPerPage)))
	targetPage := cpl / bucketsPerPage

	vector := make([]*openfhe.Ciphertext, numPages)

	// Create plaintexts for 0 and 1 (replicated to all slots)
	fullZero := make([]int64, ctx.ringDim)
	fullOne := make([]int64, ctx.ringDim)
	for i := range fullOne {
		fullOne[i] = 1
	}

	ptZero, err := ctx.CC.MakePackedPlaintext(fullZero)
	if err != nil {
		return nil, err
	}
	defer ptZero.Close()

	ptOne, err := ctx.CC.MakePackedPlaintext(fullOne)
	if err != nil {
		return nil, err
	}
	defer ptOne.Close()

	// Encrypt one-hot vector for pages
	for i := 0; i < numPages; i++ {
		var pt *openfhe.Plaintext
		if i == targetPage {
			pt = ptOne
		} else {
			pt = ptZero
		}

		ct, err := ctx.CC.Encrypt(ctx.KP, pt)
		if err != nil {
			// Clean up already created ciphertexts
			for j := 0; j < i; j++ {
				vector[j].Close()
			}
			return nil, err
		}
		vector[i] = ct
	}

	return vector, nil
}

// DecryptConnectablePeersPaged decrypts the response from Paged PIR.
// It extracts the specific slot range corresponding to the requested CPL.
func (ctx *FHEContext) DecryptConnectablePeersPaged(ct *openfhe.Ciphertext, targetCPL int) ([]ConnectablePeer, error) {
	pt, err := ctx.CC.Decrypt(ctx.KP, ct)
	if err != nil {
		return nil, err
	}
	defer pt.Close()

	fullData, err := pt.GetPackedValue()
	if err != nil {
		return nil, err
	}

	// Calculate offset for the specific bucket we wanted
	bucketsPerPage := ctx.ringDim / BucketStride
	offset := (targetCPL % bucketsPerPage) * BucketStride

	if offset+BucketStride > len(fullData) {
		return nil, errors.New("decrypted data too short for offset")
	}

	// Extract only the relevant slice for this bucket
	bucketData := fullData[offset : offset+BucketStride]

	return DeserializeConnectablePeers(bucketData)
}
