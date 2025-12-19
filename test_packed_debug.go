//go:build openfhe

package kbucket

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	"github.com/stretchr/testify/require"

	ma "github.com/multiformats/go-multiaddr"
)

func TestPackedDebug(t *testing.T) {
	// Setup FHE context with rotation
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	// Create routing table
	local := test.RandPeerIDFatal(t)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(5, localID, time.Hour, ps, time.Hour, nil, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// Add one peer at CPL 2
	peerCPL2, err := GenRandPeerIDWithCPL(localID, 2)
	require.NoError(t, err)
	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/10000")
	ps.AddAddrs(peerCPL2, []ma.Multiaddr{addr}, time.Hour)
	added, err := rt.TryAddPeer(peerCPL2, true, false)
	require.NoError(t, err)
	require.True(t, added)

	fmt.Printf("Added peer to CPL 2: %s\n", peerCPL2)
	fmt.Printf("Routing table has %d buckets\n", len(rt.buckets))

	rt.tabLock.RLock()
	for i, b := range rt.buckets {
		fmt.Printf("Bucket %d: %d peers\n", i, b.len())
	}
	rt.tabLock.RUnlock()

	// Create query for CPL 2
	queryCt, err := ctx.CreateQueryVectorPacked(2)
	require.NoError(t, err)
	defer queryCt.Close()

	// Decrypt the query to see what we sent
	pt, err := ctx.CC.Decrypt(ctx.KP, queryCt)
	require.NoError(t, err)
	querySlots, err := pt.GetPackedValue()
	pt.Close()
	require.NoError(t, err)

	fmt.Printf("Query slots (first 10): %v\n", querySlots[:10])

	// Run PIR
	response, err := rt.GetBucketPIRPacked(queryCt, ps)
	require.NoError(t, err)
	defer response.Close()

	// Decrypt response
	peers, err := ctx.DecryptConnectablePeers(response)
	require.NoError(t, err)

	fmt.Printf("Decrypted %d peers\n", len(peers))
	for _, p := range peers {
		fmt.Printf("  - %s\n", p.ID)
	}
}
