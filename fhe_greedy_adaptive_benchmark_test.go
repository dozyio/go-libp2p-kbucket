//go:build openfhe

package kbucket

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	"github.com/stretchr/testify/require"
)

// BenchmarkGreedyAdaptiveE2E measures end-to-end performance of GreedyAdaptive PIR
func BenchmarkGreedyAdaptiveE2E(b *testing.B) {
	peerCounts := []int{100, 500, 1000}

	for _, peerCount := range peerCounts {
		b.Run(fmt.Sprintf("peers_%d", peerCount), func(b *testing.B) {
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

			rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)
			require.NoError(b, err)
			rt.EnableFHE(ctx)

			// Add peers
			addedCount := 0
			for i := 0; i < peerCount*2 && addedCount < peerCount; i++ {
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

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Client: Create query
				queryVec, err := ctx.CreateQueryVectorGreedy(targetCPL)
				require.NoError(b, err)

				// Server: Process query
				responses, err := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
				require.NoError(b, err)

				// Client: Decrypt
				_, err = ctx.DecryptGreedyAdaptiveResponse(responses)
				require.NoError(b, err)

				// Cleanup
				queryVec.Close()
				for _, ct := range responses {
					ct.Close()
				}
			}
		})
	}
}

// BenchmarkGreedyAdaptiveComponents measures individual components
func BenchmarkGreedyAdaptiveComponents(b *testing.B) {
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

	rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)
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

	b.Run("QueryCreation", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			queryVec, err := ctx.CreateQueryVectorGreedy(targetCPL)
			require.NoError(b, err)
			queryVec.Close()
		}
	})

	b.Run("ServerCompute", func(b *testing.B) {
		queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
		defer queryVec.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			responses, err := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
			require.NoError(b, err)
			for _, ct := range responses {
				ct.Close()
			}
		}
	})

	b.Run("Decryption", func(b *testing.B) {
		queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
		responses, _ := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
		queryVec.Close()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := ctx.DecryptGreedyAdaptiveResponse(responses)
			require.NoError(b, err)
		}

		for _, ct := range responses {
			ct.Close()
		}
	})
}

// BenchmarkGreedyAdaptiveBandwidth measures bandwidth for different scenarios
func BenchmarkGreedyAdaptiveBandwidth(b *testing.B) {
	scenarios := []struct {
		name           string
		peerCount      int
		peersPerBucket int
	}{
		{"small_5peers", 100, 5},
		{"medium_10peers", 200, 10},
		{"large_20peers", 500, 20},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
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

			rt, err := NewRoutingTable(scenario.peersPerBucket, localID, time.Hour, ps, time.Hour, nil, nil)
			require.NoError(b, err)
			rt.EnableFHE(ctx)

			// Add peers
			addedCount := 0
			for i := 0; i < scenario.peerCount*2 && addedCount < scenario.peerCount; i++ {
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

			// Create query and response once to measure size
			queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
			responses, _ := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)

			// Estimate sizes (in production, you'd serialize these)
			// Each ciphertext is approximately 128KB based on ring dimension
			querySizeBytes := 128 * 1024 // 1 ciphertext
			responseSizeBytes := len(responses) * 128 * 1024

			b.ReportMetric(float64(querySizeBytes)/1024, "query_KB")
			b.ReportMetric(float64(responseSizeBytes)/1024, "response_KB")
			b.ReportMetric(float64(querySizeBytes+responseSizeBytes)/1024, "total_KB")
			b.ReportMetric(float64(len(responses)), "response_cts")

			// Cleanup
			queryVec.Close()
			for _, ct := range responses {
				ct.Close()
			}
		})
	}
}

// BenchmarkGreedyAdaptiveVsPaged compares GreedyAdaptive with Paged approach
func BenchmarkGreedyAdaptiveVsPaged(b *testing.B) {
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

	rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)
	require.NoError(b, err)
	rt.EnableFHE(ctx)

	// Add 500 peers with large multiaddrs
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

	b.Run("GreedyAdaptive", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
			responses, _ := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
			_, _ = ctx.DecryptGreedyAdaptiveResponse(responses)

			queryVec.Close()
			for _, ct := range responses {
				ct.Close()
			}
		}
	})

	b.Run("Paged", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			queryVec, _ := ctx.CreateQueryVector(targetCPL)
			response, _ := rt.GetBucketPIRPaged(queryVec, ps)
			_, _ = ctx.DecryptConnectablePeers(response)
			response.Close()
			for _, ct := range queryVec {
				ct.Close()
			}
		}
	})
}

// BenchmarkGreedyAdaptiveScalability tests scalability with different bucket sizes
func BenchmarkGreedyAdaptiveScalability(b *testing.B) {
	bucketSizes := []int{5, 10, 15, 20}

	for _, bucketSize := range bucketSizes {
		b.Run(fmt.Sprintf("bucket_%d", bucketSize), func(b *testing.B) {
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

			rt, err := NewRoutingTable(bucketSize, localID, time.Hour, ps, time.Hour, nil, nil)
			require.NoError(b, err)
			rt.EnableFHE(ctx)

			// Add peers to fill multiple buckets
			addedCount := 0
			for i := 0; i < 1000 && addedCount < 300; i++ {
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

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				queryVec, _ := ctx.CreateQueryVectorGreedy(targetCPL)
				responses, _ := rt.GetBucketPIRGreedyAdaptive(queryVec, ps)
				_, _ = ctx.DecryptGreedyAdaptiveResponse(responses)

				queryVec.Close()
				for _, ct := range responses {
					ct.Close()
				}
			}
		})
	}
}
