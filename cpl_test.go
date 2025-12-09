package kbucket

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	pstore "github.com/libp2p/go-libp2p/p2p/host/peerstore"
)

// TestFindOptimalMaxCPL simulates routing table depth for different network sizes.
// It calculates the average number of peers, average buckets, and maximum CPL depth
// to help determine the optimal MaxCPL parameter for FHE-based routing.
//
// usage: go test -v -run TestFindOptimalMaxCPL -timeout 30m
func TestFindOptimalMaxCPL(t *testing.T) {
	networkSizes := []int{
		100,
		1_000,
		10_000,
		100_000,
		1_000_000,
		10_000_000, // This large network simulation may take a few minutes
	}

	const k = 20                 // Standard Kademlia bucket size
	const numObserverNodes = 100 // Sample size to check table depth

	// Seed for reproducibility
	// We use a specific source to ensure deterministic results across runs
	rng := rand.New(rand.NewSource(12345))

	t.Logf("Starting simulation with k=%d, observer_samples=%d", k, numObserverNodes)
	t.Logf("%-12s | %-10s | %-12s | %-10s | %-12s | %-15s | %-15s",
		"Network Size", "AvgPeers", "TheoryPeers", "AvgBuckets", "MaxCPLSeen", "TheoryMaxCPL", "Recommended CPL")
	t.Logf("-----------------------------------------------------------------------------------------------------------------")

	for _, N := range networkSizes {
		t.Run(fmt.Sprintf("N=%d", N), func(t *testing.T) {
			if N > 1_000_000 {
				t.Logf("Generating large network (N=%d), this may take a moment...", N)
			}

			// --- 1. Generate Ground Truth Network ---
			// We generate N random peer IDs to represent the global network
			peers := make([]peer.ID, N)
			for i := 0; i < N; i++ {
				peers[i] = test.RandPeerIDFatal(t)
			}

			// Only log this for smaller networks to avoid log spam,
			// or just once to indicate progress.
			if N >= 100_000 {
				t.Logf("Generated %d peers. Selecting observers...", N)
			}

			// --- 2. Pick Observer Nodes ---
			// We select a random subset of nodes to act as our "observers".
			// We will build full routing tables for these nodes to see how deep they go.
			numObserversThisRun := numObserverNodes
			if N < numObserverNodes {
				numObserversThisRun = N
			}

			observerIndices := make([]int, numObserversThisRun)

			// If network is small, use all nodes as observers
			if N <= numObserversThisRun {
				for i := 0; i < N; i++ {
					observerIndices[i] = i
				}
			} else {
				// Otherwise pick random unique indices
				// (For simplicity in simulation we just pick random, duplicates unlikely/harmless for stats)
				for i := 0; i < numObserversThisRun; i++ {
					observerIndices[i] = rng.Intn(N)
				}
			}

			// --- 3. Run Simulation for Observers ---
			var totalPeersSum int64
			var totalBucketsSum int64
			maxBucketsSeen := 0

			metrics := pstore.NewMetrics()

			for i := 0; i < numObserversThisRun; i++ {
				obsIdx := observerIndices[i]
				localID := ConvertPeerID(peers[obsIdx])

				// Create a new routing table for this observer
				// We use a very long refresh interval because we are manually populating it
				rt, err := NewRoutingTable(k, localID, time.Hour, metrics, 100*time.Hour, nil)
				if err != nil {
					t.Fatalf("Failed to create rt: %v", err)
				}

				// Populate the table with ALL other peers in the network
				// Kademlia logic will automatically reject peers that don't fit in buckets
				for j, p := range peers {
					if j == obsIdx {
						continue // Don't add self
					}
					rt.TryAddPeer(p, true, false)
				}

				// --- Collect Metrics from the filled table ---
				rt.tabLock.RLock()
				numBuckets := len(rt.buckets)
				numPeers := rt.Size()
				rt.tabLock.RUnlock()

				totalBucketsSum += int64(numBuckets)
				totalPeersSum += int64(numPeers)

				if numBuckets > maxBucketsSeen {
					maxBucketsSeen = numBuckets
				}

				// Progress logging for large simulations
				if (i+1)%25 == 0 && N >= 100_000 {
					t.Logf("...processed observer %d/%d (current max buckets: %d)",
						i+1, numObserversThisRun, maxBucketsSeen)
				}
			}

			// --- 4. Calculate and Report Results ---
			avgPeers := float64(totalPeersSum) / float64(numObserversThisRun)
			avgBuckets := float64(totalBucketsSum) / float64(numObserversThisRun)

			// MaxCPL Calculation:
			// If a table has 15 buckets, they are indices 0..14.
			// The last bucket (index 14) covers everything from CPL 14 up to 256.
			// So the "Deepest Specific CPL" we routed to is 14.
			maxCplSeen := maxBucketsSeen - 1
			if maxCplSeen < 0 {
				maxCplSeen = 0
			}

			theoreticalMaxCPL := math.Log2(float64(N))

			// Theoretical peer count in Kademlia is roughly k * log2(N)
			theoreticalPeers := float64(k) * theoreticalMaxCPL
			if theoreticalPeers < float64(k) && N < k {
				theoreticalPeers = float64(N - 1)
			} else if theoreticalPeers > float64(N) {
				theoreticalPeers = float64(N - 1)
			}

			// Recommended CPL = MaxSeen + Safety Margin
			// We add +2:
			// +1 because maxCplSeen is 0-indexed (bucket 20 covers CPL 20+)
			// +1 for statistical safety margin against outliers
			recommendedCPL := maxCplSeen + 2

			t.Logf("%-12d | %-10.1f | %-12.1f | %-10.1f | %-12d | %-15.2f | %-15d",
				N, avgPeers, theoreticalPeers, avgBuckets, maxCplSeen, theoreticalMaxCPL, recommendedCPL)
		})
	}
}
