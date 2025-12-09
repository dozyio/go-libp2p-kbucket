//go:build openfhe

package kbucket

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	"github.com/stretchr/testify/require"
)

// TestGreedyAdaptiveLatencyBreakdown measures client vs server latency
func TestGreedyAdaptiveLatencyBreakdown(t *testing.T) {
	// Setup
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	local := test.RandPeerIDFatal(t)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// Add 500 peers
	addedCount := 0
	for i := 0; i < 1000 && addedCount < 500; i++ {
		p := test.RandPeerIDFatal(t)
		addrs := generateLargeMultiaddrs(i)
		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, true, false); added {
			addedCount++
		}
	}

	target := test.RandPeerIDFatal(t)
	targetID := ConvertPeerID(target)
	targetCPL := CommonPrefixLen(targetID, localID)

	t.Logf("Testing with %d peers in %d buckets", rt.Size(), len(rt.buckets))

	// Measure multiple rounds for accuracy
	rounds := 10
	var totalQueryCreation time.Duration
	var totalServerCompute time.Duration
	var totalDecryption time.Duration
	var totalE2E time.Duration

	for i := 0; i < rounds; i++ {
		// Full E2E timing
		e2eStart := time.Now()

		// CLIENT: Query Creation
		queryStart := time.Now()
		queryVec, err := ctx.CreateQueryVectorGreedy(targetCPL)
		queryTime := time.Since(queryStart)
		require.NoError(t, err)
		totalQueryCreation += queryTime

		// SERVER: Compute PIR
		serverStart := time.Now()
		responses, err := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
		serverTime := time.Since(serverStart)
		require.NoError(t, err)
		totalServerCompute += serverTime

		// CLIENT: Decryption
		decryptStart := time.Now()
		peers, err := ctx.DecryptGreedyAdaptiveResponse(responses)
		decryptTime := time.Since(decryptStart)
		require.NoError(t, err)
		totalDecryption += decryptTime

		e2eTime := time.Since(e2eStart)
		totalE2E += e2eTime

		if i == 0 {
			t.Logf("Retrieved %d peers from bucket", len(peers))
		}

		// Cleanup
		queryVec.Close()
		for _, ct := range responses {
			ct.Close()
		}
	}

	// Calculate averages
	avgQueryCreation := totalQueryCreation / time.Duration(rounds)
	avgServerCompute := totalServerCompute / time.Duration(rounds)
	avgDecryption := totalDecryption / time.Duration(rounds)
	avgE2E := totalE2E / time.Duration(rounds)

	// Calculate client-side total (query + decrypt)
	avgClientTotal := avgQueryCreation + avgDecryption

	// Network overhead (E2E - individual components)
	overhead := avgE2E - (avgQueryCreation + avgServerCompute + avgDecryption)

	t.Log("\n=== GREEDY ADAPTIVE LATENCY BREAKDOWN ===")
	t.Logf("Average over %d rounds:\n", rounds)

	t.Log("CLIENT-SIDE:")
	t.Logf("  1. Query Creation (encryption):  %6.2f ms", avgQueryCreation.Seconds()*1000)
	t.Logf("  2. Decryption:                    %6.2f ms", avgDecryption.Seconds()*1000)
	t.Logf("  Total Client Time:                %6.2f ms  (%.1f%%)",
		avgClientTotal.Seconds()*1000,
		float64(avgClientTotal)/float64(avgE2E)*100)

	t.Log("\nSERVER-SIDE:")
	t.Logf("  Homomorphic Computation:          %6.2f ms  (%.1f%%)",
		avgServerCompute.Seconds()*1000,
		float64(avgServerCompute)/float64(avgE2E)*100)

	t.Log("\nOVERHEAD:")
	t.Logf("  Measurement overhead:             %6.2f ms  (%.1f%%)",
		overhead.Seconds()*1000,
		float64(overhead)/float64(avgE2E)*100)

	t.Log("\nTOTAL E2E:")
	t.Logf("  End-to-End Latency:               %6.2f ms", avgE2E.Seconds()*1000)

	t.Log("\n=== BREAKDOWN BY PERCENTAGE ===")
	t.Logf("Query Creation:  %5.1f%%", float64(avgQueryCreation)/float64(avgE2E)*100)
	t.Logf("Server Compute:  %5.1f%%", float64(avgServerCompute)/float64(avgE2E)*100)
	t.Logf("Decryption:      %5.1f%%", float64(avgDecryption)/float64(avgE2E)*100)
	t.Logf("Overhead:        %5.1f%%", float64(overhead)/float64(avgE2E)*100)

	t.Log("\n=== NETWORK SIMULATION ===")
	// Simulate different network latencies
	for _, rtt := range []int{10, 50, 100, 200, 500} {
		networkLatency := time.Duration(rtt) * time.Millisecond
		simulatedE2E := avgClientTotal + avgServerCompute + networkLatency
		t.Logf("With %3d ms network RTT: Total = %6.2f ms (Client: %.1f%%, Server: %.1f%%, Network: %.1f%%)",
			rtt,
			simulatedE2E.Seconds()*1000,
			float64(avgClientTotal)/float64(simulatedE2E)*100,
			float64(avgServerCompute)/float64(simulatedE2E)*100,
			float64(networkLatency)/float64(simulatedE2E)*100)
	}
}

// BenchmarkGreedyAdaptiveLatencyComponents benchmarks each component separately
func BenchmarkGreedyAdaptiveLatencyComponents(b *testing.B) {
	// Setup
	ctx, err := NewFHEContext()
	require.NoError(b, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(b, err)
	defer ctx.Close()

	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(b, err)

	rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil)
	require.NoError(b, err)
	rt.EnableFHE(ctx)

	// Add 500 peers
	addedCount := 0
	for i := 0; i < 1000 && addedCount < 500; i++ {
		p := test.RandPeerIDFatal(b)
		addrs := generateLargeMultiaddrs(i)
		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, true, false); added {
			addedCount++
		}
	}

	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)
	targetCPL := CommonPrefixLen(targetID, localID)

	b.Run("Client_QueryCreation", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
			queryVec.Close()
		}
	})

	b.Run("Server_Compute", func(b *testing.B) {
		queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
		defer queryVec.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			responses, _ := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
			for _, ct := range responses {
				ct.Close()
			}
		}
	})

	b.Run("Client_Decryption", func(b *testing.B) {
		queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
		responses, _ := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
		queryVec.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ctx.DecryptGreedyAdaptiveResponse(responses)
		}

		for _, ct := range responses {
			ct.Close()
		}
	})

	b.Run("Client_Total", func(b *testing.B) {
		// Pre-create server response
		queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
		responses, _ := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
		queryVec.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Client creates query
			q, _ := ctx.CreateQueryVectorGreedy(targetCPL)
			// Client decrypts response
			_, _ = ctx.DecryptGreedyAdaptiveResponse(responses)
			q.Close()
		}

		for _, ct := range responses {
			ct.Close()
		}
	})
}

// TestPagedLatencyBreakdown measures Paged method for comparison
func TestPagedLatencyBreakdown(t *testing.T) {
	// Setup
	ctx, err := NewFHEContext()
	require.NoError(t, err)
	err = ctx.GenerateKeysWithRotation()
	require.NoError(t, err)
	defer ctx.Close()

	local := test.RandPeerIDFatal(t)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(t, err)

	rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil)
	require.NoError(t, err)
	rt.EnableFHE(ctx)

	// Add 500 peers
	addedCount := 0
	for i := 0; i < 1000 && addedCount < 500; i++ {
		p := test.RandPeerIDFatal(t)
		addrs := generateLargeMultiaddrs(i)
		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, true, false); added {
			addedCount++
		}
	}

	target := test.RandPeerIDFatal(t)
	targetID := ConvertPeerID(target)
	targetCPL := CommonPrefixLen(targetID, localID)

	rounds := 10
	var totalQueryCreation time.Duration
	var totalServerCompute time.Duration
	var totalDecryption time.Duration
	var totalE2E time.Duration

	for i := 0; i < rounds; i++ {
		e2eStart := time.Now()

		// CLIENT: Query Creation
		queryStart := time.Now()
		queryVec, err := ctx.CreateQueryVector(targetCPL)
		queryTime := time.Since(queryStart)
		require.NoError(t, err)
		totalQueryCreation += queryTime

		// SERVER: Compute PIR
		serverStart := time.Now()
		response, err := rt.GetBucketPIRPaged(queryVec, ps)
		serverTime := time.Since(serverStart)
		require.NoError(t, err)
		totalServerCompute += serverTime

		// CLIENT: Decryption
		decryptStart := time.Now()
		peers, err := ctx.DecryptConnectablePeers(response)
		decryptTime := time.Since(decryptStart)
		require.NoError(t, err)
		totalDecryption += decryptTime

		e2eTime := time.Since(e2eStart)
		totalE2E += e2eTime

		if i == 0 {
			t.Logf("Retrieved %d peers from bucket", len(peers))
		}

		// Cleanup
		response.Close()
		for _, ct := range queryVec {
			ct.Close()
		}
	}

	// Calculate averages
	avgQueryCreation := totalQueryCreation / time.Duration(rounds)
	avgServerCompute := totalServerCompute / time.Duration(rounds)
	avgDecryption := totalDecryption / time.Duration(rounds)
	avgE2E := totalE2E / time.Duration(rounds)
	avgClientTotal := avgQueryCreation + avgDecryption

	t.Log("\n=== PAGED LATENCY BREAKDOWN ===")
	t.Logf("Average over %d rounds:\n", rounds)

	t.Log("CLIENT-SIDE:")
	t.Logf("  1. Query Creation (24 CTs):      %6.2f ms", avgQueryCreation.Seconds()*1000)
	t.Logf("  2. Decryption:                    %6.2f ms", avgDecryption.Seconds()*1000)
	t.Logf("  Total Client Time:                %6.2f ms  (%.1f%%)",
		avgClientTotal.Seconds()*1000,
		float64(avgClientTotal)/float64(avgE2E)*100)

	t.Log("\nSERVER-SIDE:")
	t.Logf("  Homomorphic Computation:          %6.2f ms  (%.1f%%)",
		avgServerCompute.Seconds()*1000,
		float64(avgServerCompute)/float64(avgE2E)*100)

	t.Log("\nTOTAL E2E:")
	t.Logf("  End-to-End Latency:               %6.2f ms", avgE2E.Seconds()*1000)

	t.Log("\n=== BREAKDOWN BY PERCENTAGE ===")
	t.Logf("Query Creation:  %5.1f%%", float64(avgQueryCreation)/float64(avgE2E)*100)
	t.Logf("Server Compute:  %5.1f%%", float64(avgServerCompute)/float64(avgE2E)*100)
	t.Logf("Decryption:      %5.1f%%", float64(avgDecryption)/float64(avgE2E)*100)
}
