//go:build openfhe

package kbucket

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"

	// Import the correct test package
	"github.com/libp2p/go-libp2p/core/test"
	// Import the 'pstoremem' implementation
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	"github.com/stretchr/testify/require"

	// Import the multiaddr package to create addresses manually
	ma "github.com/multiformats/go-multiaddr"
)

func TestFHEPIRRouting(t *testing.T) {
	// 1. Setup Context
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeys()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Table with small bucket size to force splits
	local := test.RandPeerIDFatal(t)
	// We need to pass a valid peerstore to rt.metrics to look up addresses
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	// FIX 1: Pass 'ps' directly. The Peerstore interface embeds the Metrics interface.
	rt, err := NewRoutingTable(5, ConvertPeerID(local), time.Hour, ps, time.Hour, nil, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Add Peers (Populate table)
	// Add enough peers to create at least 2-3 buckets
	var addedPeers []peer.ID
	for i := 0; i < 50; i++ {
		p := test.RandPeerIDFatal(t)

		// FIX 2: Manually create a multiaddr since RandTestMultiaddrs doesn't exist here.
		addrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000+i)
		addr, err := ma.NewMultiaddr(addrStr)
		require.NoError(t, err) // Ensure the address is valid
		addrs := []ma.Multiaddr{addr}

		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, true, false); added {
			addedPeers = append(addedPeers, p)
		}
	}
	t.Logf("Table has %d buckets and %d peers", len(rt.buckets), rt.Size())
	require.Greater(t, rt.Size(), 0, "Routing table should have peers")

	// 4. Define a Target ID
	target := test.RandPeerIDFatal(t)
	targetID := ConvertPeerID(target)
	localID := ConvertPeerID(local)

	// 5. Client Side: Calculate CPL
	cpl := CommonPrefixLen(targetID, localID)
	t.Logf("Target CPL: %d", cpl)

	// 6. Client Side: Create Query Vector
	queryVec, err := ctx.CreateQueryVector(cpl)
	require.NoError(t, err)
	defer func() {
		for _, ct := range queryVec {
			ct.Close()
		}
	}()

	// 7. Server Side: Handle PIR
	start := time.Now()
	// Pass 'ps' as the new argument
	encryptedResponse, err := rt.GetBucketPIR(queryVec, ps)
	require.NoError(t, err)
	defer encryptedResponse.Close()
	t.Logf("PIR Lookup Time: %v", time.Since(start))

	// 8. Client Side: Decrypt
	connectablePeers, err := ctx.DecryptConnectablePeers(encryptedResponse)
	require.NoError(t, err)
	t.Logf("Decrypted %d peers", len(connectablePeers))

	// 9. Verification
	// We verify that the returned peers actually belong to the bucket
	// that covers the requested CPL.

	// Find expected bucket index manually
	expectedBucketIdx := cpl
	rt.tabLock.RLock()
	if expectedBucketIdx >= len(rt.buckets) {
		expectedBucketIdx = len(rt.buckets) - 1
	}
	// Get the internal PeerInfo structs
	expectedInternalPeers := rt.buckets[expectedBucketIdx].peers()
	rt.tabLock.RUnlock()

	// Build the *expected* list of ConnectablePeer
	expectedConnectablePeers := make([]ConnectablePeer, 0)
	for _, pInfo := range expectedInternalPeers {
		addrs := ps.Addrs(pInfo.Id)
		if len(addrs) > 0 {
			expectedConnectablePeers = append(expectedConnectablePeers, ConnectablePeer{
				ID:    pInfo.Id,
				Addrs: addrs,
			})
		}
	}

	// Check that the decrypted peers match the expected connectable peers
	require.Equal(t, len(expectedConnectablePeers), len(connectablePeers), "Should return correct number of peers")

	// Verify IDs match
	peerMap := make(map[string]bool)
	for _, p := range connectablePeers {
		peerMap[p.ID.String()] = true
	}

	for _, p := range expectedConnectablePeers {
		require.True(t, peerMap[p.ID.String()], "Missing peer %s", p.ID)
	}
}

// -----------------------------------------------------------------
// NEW EXHAUSTIVE TEST
// -----------------------------------------------------------------

// addPeerWithCPL is a test helper to generate a peer with a specific CPL
// relative to the localID and add it to the routing table and peerstore.
func addPeerWithCPL(t *testing.T, rt *RoutingTable, ps peerstore.Peerstore, localID ID, cpl int) peer.ID {
	// GenRandPeerIDWithCPL is in util.go, which is part of the kbucket package
	p, err := GenRandPeerIDWithCPL(localID, uint(cpl))
	require.NoError(t, err)

	addrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000+cpl)
	addr, err := ma.NewMultiaddr(addrStr)
	require.NoError(t, err)

	ps.AddAddrs(p, []ma.Multiaddr{addr}, time.Hour)

	added, err := rt.TryAddPeer(p, true, false)
	require.NoError(t, err)
	require.True(t, added, "Failed to add peer with CPL %d", cpl)
	return p
}

// TestFHEPIRRouting_Exhaustive tests all edge cases of the PIR logic,
// especially the "catch-all" bucket summation.
func TestFHEPIRRouting_Exhaustive(t *testing.T) {
	// 1. Setup Context
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeys()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Table and Peerstore
	local := test.RandPeerIDFatal(t)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	// k=5, 1 bucket.
	rt, err := NewRoutingTable(5, localID, time.Hour, ps, time.Hour, nil, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Populate table with known peers at specific CPLs
	// We will create a table with 5 buckets (CPLs 0, 1, 2, 3, 4)
	// We intentionally leave CPL 1 empty.
	peerCPL0 := addPeerWithCPL(t, rt, ps, localID, 0)
	// CPL 1 is empty
	peerCPL2 := addPeerWithCPL(t, rt, ps, localID, 2)
	_ = addPeerWithCPL(t, rt, ps, localID, 3)
	// Add 5 peers to CPL 4 to force it to be the last bucket
	var peersCPL4 []peer.ID
	for i := 0; i < 5; i++ {
		peersCPL4 = append(peersCPL4, addPeerWithCPL(t, rt, ps, localID, 4))
	}

	rt.tabLock.RLock()
	lastBucketIdx := len(rt.buckets) - 1
	rt.tabLock.RUnlock()

	t.Logf("Table created with %d buckets. Last bucket index: %d", len(rt.buckets), lastBucketIdx)
	// Our setup should result in 5 buckets (0-4), so lastBucketIdx should be 4.
	require.Equal(t, 4, lastBucketIdx, "Test setup failed, expected 5 buckets")

	// Helper function to run a single PIR query and verify the result
	runQuery := func(queryCPL int, expectedPeerIDs ...peer.ID) func(t *testing.T) {
		return func(t *testing.T) {
			// --- Client Side ---
			queryVec, err := ctx.CreateQueryVector(queryCPL)
			require.NoError(t, err)
			defer func() {
				for _, ct := range queryVec {
					ct.Close()
				}
			}()

			// --- Server Side ---
			encryptedResponse, err := rt.GetBucketPIR(queryVec, ps)
			require.NoError(t, err)
			defer encryptedResponse.Close()

			// --- Client Side ---
			connectablePeers, err := ctx.DecryptConnectablePeers(encryptedResponse)
			require.NoError(t, err)

			// --- Verification ---
			require.Equal(t, len(expectedPeerIDs), len(connectablePeers), "Should return correct number of peers")

			peerMap := make(map[string]bool)
			for _, p := range connectablePeers {
				peerMap[p.ID.String()] = true
			}
			for _, expectedID := range expectedPeerIDs {
				require.True(t, peerMap[expectedID.String()], "Missing expected peer %s", expectedID)
			}
		}
	}

	// 4. Run Subtests
	t.Run("Query for CPL 0 (Standard Bucket)", runQuery(0, peerCPL0))

	t.Run("Query for CPL 2 (Standard Bucket)", runQuery(2, peerCPL2))

	t.Run("Query for CPL 1 (Empty Bucket)", runQuery(1)) // Expect 0 peers

	t.Run("Query for CPL 4 (Catch-All Boundary)", runQuery(4, peersCPL4...))

	t.Run("Query for CPL 10 (Catch-All Deep)", runQuery(10, peersCPL4...))

	t.Run("Query for CPL 23 (Max CPL)", runQuery(23, peersCPL4...))
}

// -----------------------------------------------------------------
// PACKED PIR TESTS (Optimized Single Ciphertext Approach)
// -----------------------------------------------------------------

// TestFHEPIRRoutingPacked tests the packed single-ciphertext PIR approach
func TestFHEPIRRoutingPacked(t *testing.T) {
	// 1. Setup Context with rotation keys
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Table
	local := test.RandPeerIDFatal(t)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(5, ConvertPeerID(local), time.Hour, ps, time.Hour, nil, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Add Peers
	var addedPeers []peer.ID
	for i := 0; i < 50; i++ {
		p := test.RandPeerIDFatal(t)

		addrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000+i)
		addr, err := ma.NewMultiaddr(addrStr)
		require.NoError(t, err)
		addrs := []ma.Multiaddr{addr}

		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, true, false); added {
			addedPeers = append(addedPeers, p)
		}
	}
	t.Logf("Table has %d buckets and %d peers", len(rt.buckets), rt.Size())
	require.Greater(t, rt.Size(), 0, "Routing table should have peers")

	// 4. Define a Target ID
	target := test.RandPeerIDFatal(t)
	targetID := ConvertPeerID(target)
	localID := ConvertPeerID(local)

	// 5. Client Side: Calculate CPL
	cpl := CommonPrefixLen(targetID, localID)
	t.Logf("Target CPL: %d", cpl)

	// 6. Client Side: Create Packed Query Vector
	start := time.Now()
	queryCt, err := ctx.CreateQueryVectorPacked(cpl)
	require.NoError(t, err)
	defer queryCt.Close()
	t.Logf("Packed Query Creation Time: %v", time.Since(start))

	// 7. Server Side: Handle PIR with Packed Query
	start = time.Now()
	encryptedResponse, err := rt.GetBucketPIRPacked(queryCt, ps)
	require.NoError(t, err)
	defer encryptedResponse.Close()
	t.Logf("PIR Lookup Time (Packed): %v", time.Since(start))

	// 8. Client Side: Decrypt
	connectablePeers, err := ctx.DecryptConnectablePeers(encryptedResponse)
	require.NoError(t, err)
	t.Logf("Decrypted %d peers", len(connectablePeers))

	// 9. Verification - same as original
	expectedBucketIdx := cpl
	rt.tabLock.RLock()
	if expectedBucketIdx >= len(rt.buckets) {
		expectedBucketIdx = len(rt.buckets) - 1
	}
	expectedInternalPeers := rt.buckets[expectedBucketIdx].peers()
	rt.tabLock.RUnlock()

	expectedConnectablePeers := make([]ConnectablePeer, 0)
	for _, pInfo := range expectedInternalPeers {
		addrs := ps.Addrs(pInfo.Id)
		if len(addrs) > 0 {
			expectedConnectablePeers = append(expectedConnectablePeers, ConnectablePeer{
				ID:    pInfo.Id,
				Addrs: addrs,
			})
		}
	}

	require.Equal(t, len(expectedConnectablePeers), len(connectablePeers), "Should return correct number of peers")

	// Verify IDs match
	peerMap := make(map[string]bool)
	for _, p := range connectablePeers {
		peerMap[p.ID.String()] = true
	}

	for _, p := range expectedConnectablePeers {
		require.True(t, peerMap[p.ID.String()], "Missing peer %s", p.ID)
	}
}

// TestFHEPIRRoutingPacked_Exhaustive tests all edge cases with packed PIR
func TestFHEPIRRoutingPacked_Exhaustive(t *testing.T) {
	// 1. Setup Context with rotation keys
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Table and Peerstore
	local := test.RandPeerIDFatal(t)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(5, localID, time.Hour, ps, time.Hour, nil, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Populate table with known peers at specific CPLs
	peerCPL0 := addPeerWithCPL(t, rt, ps, localID, 0)
	peerCPL2 := addPeerWithCPL(t, rt, ps, localID, 2)
	_ = addPeerWithCPL(t, rt, ps, localID, 3)
	var peersCPL4 []peer.ID
	for i := 0; i < 5; i++ {
		peersCPL4 = append(peersCPL4, addPeerWithCPL(t, rt, ps, localID, 4))
	}

	rt.tabLock.RLock()
	lastBucketIdx := len(rt.buckets) - 1
	rt.tabLock.RUnlock()

	t.Logf("Table created with %d buckets. Last bucket index: %d", len(rt.buckets), lastBucketIdx)

	// Helper function to run a single PIR query with packed approach
	runPackedQuery := func(queryCPL int, expectedPeerIDs ...peer.ID) func(t *testing.T) {
		return func(t *testing.T) {
			// --- Client Side ---
			queryCt, err := ctx.CreateQueryVectorPacked(queryCPL)
			require.NoError(t, err)
			defer queryCt.Close()

			// --- Server Side ---
			encryptedResponse, err := rt.GetBucketPIRPacked(queryCt, ps)
			require.NoError(t, err)
			defer encryptedResponse.Close()

			// --- Client Side ---
			connectablePeers, err := ctx.DecryptConnectablePeers(encryptedResponse)
			require.NoError(t, err)

			// --- Verification ---
			require.Equal(t, len(expectedPeerIDs), len(connectablePeers), "Should return correct number of peers")

			peerMap := make(map[string]bool)
			for _, p := range connectablePeers {
				peerMap[p.ID.String()] = true
			}
			for _, expectedID := range expectedPeerIDs {
				require.True(t, peerMap[expectedID.String()], "Missing expected peer %s", expectedID)
			}
		}
	}

	// 4. Run Subtests with packed approach
	t.Run("Packed: Query for CPL 0 (Standard Bucket)", runPackedQuery(0, peerCPL0))
	t.Run("Packed: Query for CPL 2 (Standard Bucket)", runPackedQuery(2, peerCPL2))
	t.Run("Packed: Query for CPL 1 (Empty Bucket)", runPackedQuery(1)) // Expect 0 peers
	t.Run("Packed: Query for CPL 4 (Catch-All Boundary)", runPackedQuery(4, peersCPL4...))
	t.Run("Packed: Query for CPL 10 (Catch-All Deep)", runPackedQuery(10, peersCPL4...))
	t.Run("Packed: Query for CPL 23 (Max CPL)", runPackedQuery(23, peersCPL4...))
}

// TestFHEPIRRoutingPaged tests the Paged (Spatial Packing) PIR approach
func TestFHEPIRRoutingPaged(t *testing.T) {
	// 1. Setup Context
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeys()
	require.NoError(t, err)
	defer ctx.Close()

	// 2. Setup Table
	local := test.RandPeerIDFatal(t)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(5, ConvertPeerID(local), time.Hour, ps, time.Hour, nil, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// 3. Add Peers
	var addedPeers []peer.ID
	for i := 0; i < 50; i++ {
		p := test.RandPeerIDFatal(t)

		addrStr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000+i)
		addr, err := ma.NewMultiaddr(addrStr)
		require.NoError(t, err)
		addrs := []ma.Multiaddr{addr}

		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, true, false); added {
			addedPeers = append(addedPeers, p)
		}
	}
	t.Logf("Table has %d buckets and %d peers", len(rt.buckets), rt.Size())
	require.Greater(t, rt.Size(), 0, "Routing table should have peers")

	// 4. Define a Target ID
	target := test.RandPeerIDFatal(t)
	targetID := ConvertPeerID(target)
	localID := ConvertPeerID(local)

	// 5. Client Side: Calculate CPL
	cpl := CommonPrefixLen(targetID, localID)
	t.Logf("Target CPL: %d", cpl)

	// 6. Client Side: Create Paged Query Vector
	start := time.Now()
	queryVector, err := ctx.CreateQueryVectorPaged(cpl)
	require.NoError(t, err)
	defer func() {
		for _, ct := range queryVector {
			ct.Close()
		}
	}()
	t.Logf("Paged Query Creation Time: %v (%d ciphertexts)", time.Since(start), len(queryVector))

	// 7. Server Side: Handle PIR with Paged Query
	start = time.Now()
	encryptedResponse, err := rt.GetBucketPIRPaged(queryVector, ps)
	require.NoError(t, err)
	defer encryptedResponse.Close()
	t.Logf("PIR Lookup Time (Paged): %v", time.Since(start))

	// 8. Client Side: Decrypt with target CPL
	connectablePeers, err := ctx.DecryptConnectablePeersPaged(encryptedResponse, cpl)
	require.NoError(t, err)
	t.Logf("Decrypted %d peers", len(connectablePeers))

	// 9. Verification
	expectedBucketIdx := cpl
	rt.tabLock.RLock()
	if expectedBucketIdx >= len(rt.buckets) {
		expectedBucketIdx = len(rt.buckets) - 1
	}
	expectedInternalPeers := rt.buckets[expectedBucketIdx].peers()
	rt.tabLock.RUnlock()

	expectedConnectablePeers := make([]ConnectablePeer, 0)
	for _, pInfo := range expectedInternalPeers {
		addrs := ps.Addrs(pInfo.Id)
		if len(addrs) > 0 {
			expectedConnectablePeers = append(expectedConnectablePeers, ConnectablePeer{
				ID:    pInfo.Id,
				Addrs: addrs,
			})
		}
	}

	require.Equal(t, len(expectedConnectablePeers), len(connectablePeers), "Should return correct number of peers")

	// Verify IDs match
	peerMap := make(map[string]bool)
	for _, p := range connectablePeers {
		peerMap[p.ID.String()] = true
	}

	for _, p := range expectedConnectablePeers {
		require.True(t, peerMap[p.ID.String()], "Missing peer %s", p.ID)
	}
}
