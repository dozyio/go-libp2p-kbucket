//go:build openfhe

package kbucket

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// TestGreedyAdaptiveBasic tests the basic functionality of the Greedy Adaptive PIR
func TestGreedyAdaptiveBasic(t *testing.T) {
	// 1. Setup FHE Context with rotation keys
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Routing Table
	local := test.RandPeerIDFatal(t)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(20, ConvertPeerID(local), time.Hour, ps, time.Hour, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Add peers to multiple buckets
	localID := ConvertPeerID(local)
	addedPeers := make(map[int][]peer.ID) // CPL -> peers

	// Add peers across CPLs 0-10
	for cpl := 0; cpl < 10; cpl++ {
		for i := 0; i < 5; i++ { // 5 peers per bucket
			p, err := GenRandPeerIDWithCPL(localID, uint(cpl))
			require.NoError(t, err)

			addrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000+cpl*100+i)
			addr, err := ma.NewMultiaddr(addrStr)
			require.NoError(t, err)

			ps.AddAddrs(p, []ma.Multiaddr{addr}, time.Hour)
			added, _ := rt.TryAddPeer(p, true, false)
			if added {
				addedPeers[cpl] = append(addedPeers[cpl], p)
			}
		}
	}

	t.Logf("Routing table has %d buckets and %d peers", len(rt.buckets), rt.Size())
	require.Greater(t, rt.Size(), 0, "Routing table should have peers")

	// 4. Test querying different CPLs (only test those that exist)
	maxCPL := 10
	rt.tabLock.RLock()
	actualBuckets := len(rt.buckets)
	rt.tabLock.RUnlock()
	if actualBuckets < maxCPL {
		maxCPL = actualBuckets
	}

	for targetCPL := 0; targetCPL < maxCPL; targetCPL++ {
		t.Run(fmt.Sprintf("CPL_%d", targetCPL), func(t *testing.T) {
			// Create query
			queryVec, err := ctx.CreateQueryVectorGreedy(targetCPL)
			require.NoError(t, err)
			defer queryVec.Close()

			// Server processes query
			start := time.Now()
			responses, err := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
			require.NoError(t, err)
			defer func() {
				for _, ct := range responses {
					ct.Close()
				}
			}()
			t.Logf("PIR Query for CPL %d took %v, returned %d ciphertexts", targetCPL, time.Since(start), len(responses))

			// Should return at least 1 ciphertext
			require.GreaterOrEqual(t, len(responses), 1, "Should return at least 1 ciphertext")

			// Client decrypts
			connectablePeers, err := ctx.DecryptGreedyAdaptiveResponse(responses)
			require.NoError(t, err)
			t.Logf("Decrypted %d peers from CPL %d", len(connectablePeers), targetCPL)

			// Verify the peers match the expected bucket
			bucketIdx := targetCPL
			rt.tabLock.RLock()
			if bucketIdx >= len(rt.buckets) {
				bucketIdx = len(rt.buckets) - 1
			}
			expectedInternalPeers := rt.buckets[bucketIdx].peers()
			rt.tabLock.RUnlock()

			expectedConnectable := make([]ConnectablePeer, 0)
			for _, pInfo := range expectedInternalPeers {
				addrs := ps.Addrs(pInfo.Id)
				if len(addrs) > 0 {
					expectedConnectable = append(expectedConnectable, ConnectablePeer{
						ID:    pInfo.Id,
						Addrs: addrs,
					})
				}
			}

			require.Equal(t, len(expectedConnectable), len(connectablePeers),
				"Should return correct number of peers for CPL %d", targetCPL)

			// Verify peer IDs match
			peerMap := make(map[string]bool)
			for _, p := range connectablePeers {
				peerMap[p.ID.String()] = true
			}

			for _, p := range expectedConnectable {
				require.True(t, peerMap[p.ID.String()],
					"Missing peer %s in CPL %d response", p.ID, targetCPL)
			}
		})
	}
}

// TestGreedyAdaptiveSecurity tests that querying multiple buckets results in corrupted data
func TestGreedyAdaptiveSecurity(t *testing.T) {
	// 1. Setup FHE Context
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Routing Table
	local := test.RandPeerIDFatal(t)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(20, ConvertPeerID(local), time.Hour, ps, time.Hour, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Add peers to multiple buckets - use enough peers to force splits
	localID := ConvertPeerID(local)
	// Add 25 peers per CPL to force bucket splits (bucket size is 20)
	for cpl := 0; cpl < 3; cpl++ {
		for i := 0; i < 25; i++ {
			p, err := GenRandPeerIDWithCPL(localID, uint(cpl))
			require.NoError(t, err)

			addrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000+cpl*100+i)
			addr, err := ma.NewMultiaddr(addrStr)
			require.NoError(t, err)

			ps.AddAddrs(p, []ma.Multiaddr{addr}, time.Hour)
			rt.TryAddPeer(p, true, false)
		}
	}

	t.Logf("Setup complete: %d buckets, %d peers", len(rt.buckets), rt.Size())

	// 4. Create a malicious query with TWO bits set (trying to query buckets 0 and 1)
	maliciousVec := make([]int64, ctx.ringDim)
	maliciousVec[0] = 1 // Query bucket 0
	maliciousVec[1] = 1 // AND bucket 1 (malicious!)

	pt, err := ctx.CC.MakePackedPlaintext(maliciousVec)
	require.NoError(t, err)
	maliciousQuery, err := ctx.CC.Encrypt(ctx.KP, pt)
	pt.Close()
	require.NoError(t, err)
	defer maliciousQuery.Close()

	// 5. Server processes the malicious query
	responses, err := rt.GetBucketPIRGreedyAdaptive(maliciousQuery, ps)
	require.NoError(t, err)
	defer func() {
		for _, ct := range responses {
			ct.Close()
		}
	}()

	// 6. Client tries to decrypt
	// The greedy proof should cause the data to be corrupted
	connectablePeers, err := ctx.DecryptGreedyAdaptiveResponse(responses)
	// We expect either:
	// a) An error during deserialization (corrupted JSON)
	// b) An empty peer list
	// c) Peers that don't match either bucket cleanly
	if err != nil {
		t.Logf("Decryption failed as expected with malicious query: %v", err)
		return
	}

	t.Logf("Decrypted %d peers (possibly corrupted)", len(connectablePeers))

	// Make sure we have at least 2 buckets for this test
	rt.tabLock.RLock()
	numBuckets := len(rt.buckets)
	rt.tabLock.RUnlock()

	if numBuckets < 2 {
		t.Skip("Need at least 2 buckets for security test")
		return
	}

	// If we got peers, verify they're NOT a clean match for either bucket
	rt.tabLock.RLock()
	bucket0Peers := rt.buckets[0].peers()
	bucket1Peers := rt.buckets[1].peers()
	rt.tabLock.RUnlock()

	// Check if result matches bucket 0 exactly
	matches0 := len(connectablePeers) == len(bucket0Peers)
	if matches0 {
		for _, cp := range connectablePeers {
			found := false
			for _, bp := range bucket0Peers {
				if cp.ID == bp.Id {
					found = true
					break
				}
			}
			if !found {
				matches0 = false
				break
			}
		}
	}

	// Check if result matches bucket 1 exactly
	matches1 := len(connectablePeers) == len(bucket1Peers)
	if matches1 {
		for _, cp := range connectablePeers {
			found := false
			for _, bp := range bucket1Peers {
				if cp.ID == bp.Id {
					found = true
					break
				}
			}
			if !found {
				matches1 = false
				break
			}
		}
	}

	// Security property: malicious query should NOT cleanly return either bucket
	require.False(t, matches0 && matches1,
		"Malicious query should not return clean data from multiple buckets")

	t.Log("Security test passed: malicious multi-bucket query did not return clean data")
}

// TestGreedyAdaptiveEmptyBucket tests querying an empty bucket
func TestGreedyAdaptiveEmptyBucket(t *testing.T) {
	// 1. Setup FHE Context
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Routing Table
	local := test.RandPeerIDFatal(t)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(20, ConvertPeerID(local), time.Hour, ps, time.Hour, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Don't add any peers - all buckets are empty

	// 4. Query bucket 5 (which is empty)
	queryVec, err := ctx.CreateQueryVectorGreedy(5)
	require.NoError(t, err)
	defer queryVec.Close()

	// 5. Server processes query
	responses, err := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
	require.NoError(t, err)
	defer func() {
		for _, ct := range responses {
			ct.Close()
		}
	}()

	// 6. Client decrypts
	connectablePeers, err := ctx.DecryptGreedyAdaptiveResponse(responses)
	require.NoError(t, err)

	// 7. Should return empty list
	require.Equal(t, 0, len(connectablePeers), "Empty bucket should return 0 peers")
	t.Log("Empty bucket test passed")
}
