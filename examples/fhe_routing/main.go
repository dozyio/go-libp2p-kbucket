//go:build openfhe

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dozyio/openfhe-go/openfhe"
	kbucket "github.com/libp2p/go-libp2p-kbucket"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	ma "github.com/multiformats/go-multiaddr"
)

// This example demonstrates privacy-preserving routing table lookups using FHE
// with the new Strategy Pattern API.
//
// Scenario:
//   - Server hosts a routing table with multiple peers
//   - Client wants to find peers close to a target ID
//   - Client doesn't want to reveal the target ID to the server
//   - Server uses PIR to return the bucket without learning the target
//   - Client filters locally to find the K-nearest peers
//
// The new Strategy Pattern allows easy switching between PIR methods:
//   - Standard: 24 ciphertexts (no rotation keys)
//   - Paged: 1-24 ciphertexts depending on ring size (no rotation keys)
//   - Greedy Adaptive: 1 ciphertext query (requires rotation keys)
//   - Greedy Normalized: Same as Greedy but with normalized bucket sizes (recommended)
//
// To run this example:
//   1. Install OpenFHE C++ library: https://github.com/openfheorg/openfhe-development
//   2. Build with: go build -tags openfhe
//   3. Run: ./fhe_routing

func main() {
	fmt.Println("=== FHE-Based Private Routing Table Lookup (Strategy Pattern) ===")

	bucketSize := 20

	// Step 1: Set up FHE context
	fmt.Println("1. Setting up FHE context...")
	fheCtx, err := kbucket.NewFHEContext()
	if err != nil {
		log.Fatalf("Failed to create FHE context: %v", err)
	}
	defer fheCtx.Close()

	// Step 2: Choose PIR strategy
	strategy := kbucket.PIRStrategyGreedyNormalized

	// Step 3: Generate keys for chosen strategy
	fmt.Printf("2. Generating keys for strategy: %s...\n", strategy)
	err = fheCtx.GenerateKeysForStrategy(strategy)
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	// Show strategy metadata
	metadata := kbucket.GetStrategyMetadata(strategy, fheCtx.RingDim())
	fmt.Printf("   Strategy: %s\n", metadata.Name)
	fmt.Printf("   Rotation keys: %.2f MB\n", metadata.RotationKeySizeMB)
	fmt.Printf("   Query size: %.2f MB\n", metadata.QuerySizeMB)
	fmt.Printf("   Recommended for: %s\n", metadata.RecommendedFor)

	// Show actual key sizes
	ccBytes, _ := openfhe.SerializeCryptoContextToBytes(fheCtx.CC)
	fmt.Printf("\n   Actual sizes:\n")
	fmt.Printf("   Context (Params):     %s\n", formatSize(len(ccBytes)))

	pkBytes, _ := openfhe.SerializePublicKeyToBytes(fheCtx.KP)
	fmt.Printf("   Public Key:           %s\n", formatSize(len(pkBytes)))

	skBytes, _ := openfhe.SerializePrivateKeyToBytes(fheCtx.KP)
	fmt.Printf("   Private Key:          %s\n", formatSize(len(skBytes)))

	multBytes, _ := openfhe.SerializeEvalMultKeyToBytes(fheCtx.CC, "")
	fmt.Printf("   Relinearization Key:  %s\n", formatSize(len(multBytes)))

	rotBytes, _ := openfhe.SerializeEvalAutomorphismKeyToBytes(fheCtx.CC, "")
	fmt.Printf("   Rotation Keys (Total):%s\n", formatSize(len(rotBytes)))

	// Step 4: Create PIR config
	pirConfig := &kbucket.PIRConfig{
		Strategy:     strategy,
		BucketStride: 0, // 0 = auto-calculate optimal
		FHEContext:   fheCtx,
	}

	// Step 5: Create server's routing table with PIR
	fmt.Println("\n3. Creating server routing table with PIR enabled...")
	localPeer := test.RandPeerIDFatal(nil)
	localID := kbucket.ConvertPeerID(localPeer)

	ps, err := pstoremem.NewPeerstore()
	if err != nil {
		log.Fatalf("Failed to create peerstore: %v", err)
	}

	rt, err := kbucket.NewRoutingTable(
		bucketSize,    // bucket size
		localID,       // local node ID
		time.Hour,     // max latency
		ps,            // peerstore (metrics)
		100*time.Hour, // usefulness grace period
		nil,           // peer diversity filter
		pirConfig,     // PIR configuration (REQUIRED)
	)
	if err != nil {
		log.Fatalf("Failed to create routing table: %v", err)
	}

	fmt.Printf("   ✓ Routing table created for peer %s\n", localPeer.String()[:16]+"...")
	fmt.Printf("   ✓ PIR enabled with: %s\n", rt.PIRStrategyName())

	// Step 6: Populate routing table with peers
	fmt.Println("\n4. Populating routing table with peers...")

	peers := make([]peer.ID, 0, 100000)

	for cpl := range 16 {
		peersForCPL := bucketSize
		for i := range peersForCPL {
			p, err := kbucket.GenRandPeerIDWithCPL(localID, uint(cpl))
			if err != nil {
				continue
			}

			addrStr := fmt.Sprintf("/ip4/127.0.0.%d/tcp/%d", cpl+1, 10000+i)
			addr, err := ma.NewMultiaddr(addrStr)
			if err != nil {
				continue
			}
			ps.AddAddrs(p, []ma.Multiaddr{addr}, time.Hour)

			added, err := rt.TryAddPeer(p, true, true)
			if err != nil {
				continue
			}
			if added {
				peers = append(peers, p)
			}
		}
	}

	fmt.Printf("   ✓ Added %d peers to routing table\n", rt.Size())
	fmt.Printf("   ✓ Routing table will auto-expand as needed (bucket splitting)\n")

	// Step 7: Client creates a target ID (what they're searching for)
	fmt.Println("\n5. Client selects target peer to search for...")
	if len(peers) == 0 {
		log.Fatalf("No peers were added to the routing table")
	}
	targetPeer := peers[len(peers)/2]
	targetID := kbucket.ConvertPeerID(targetPeer)
	targetCPL := kbucket.CommonPrefixLen(localID, targetID)
	fmt.Printf("   Target peer: %s\n", targetPeer.String()[:16]+"...")
	fmt.Printf("   Target CPL:  %d\n", targetCPL)

	// Step 8: Traditional (non-private) lookup for comparison
	fmt.Println("\n6. Traditional lookup (server learns target)...")
	lookupCPL := kbucket.CommonPrefixLen(targetID, localID)
	fmt.Printf("   Bucket index used: %d (based on CPL between target and local node)\n", lookupCPL)
	start := time.Now()
	traditionalPeers := rt.NearestPeers(targetID, 20)
	traditionalDuration := time.Since(start)
	fmt.Printf("   Found %d peers in %v\n", len(traditionalPeers), traditionalDuration)

	// Step 9: FHE-based private lookup using new unified API
	fmt.Println("\n7. FHE-based private lookup (using new GetBucket API)...")

	queryStart := time.Now()
	bucketPeers, err := rt.GetBucket(targetCPL, ps)
	if err != nil {
		log.Fatalf("PIR query failed: %v", err)
	}
	queryDuration := time.Since(queryStart)

	fmt.Printf("   ✓ Retrieved %d peers in %v\n", len(bucketPeers), queryDuration)
	fmt.Printf("   ✓ Server never learned target ID!\n")
	fmt.Printf("   ✓ Using strategy: %s\n", rt.PIRStrategyName())

	// Step 10: Client filters locally
	fmt.Println("\n8. Client filters locally to find K-nearest...")
	bucketPeerIDs := make([]peer.ID, len(bucketPeers))
	for i, cp := range bucketPeers {
		bucketPeerIDs[i] = cp.ID
	}
	kNearest := findKNearest(bucketPeerIDs, targetID, 20)
	fmt.Printf("   ✓ Found %d nearest peers\n", len(kNearest))

	// Step 11: Compare results
	fmt.Println("\n9. Comparing results...")
	fmt.Printf("   Traditional time: %v\n", traditionalDuration)
	fmt.Printf("   FHE time:         %v (%.1fx slower)\n",
		queryDuration, float64(queryDuration)/float64(traditionalDuration))
	fmt.Printf("   \n")
	fmt.Printf("   Privacy gain: Target ID completely hidden from server\n")

	// Verify correctness
	matches := 0
	fmt.Println("\n10. Verifying similar results...")

	tradMap := make(map[peer.ID]bool)
	for _, p := range traditionalPeers {
		tradMap[p] = true
	}

	for _, p := range kNearest {
		if tradMap[p] {
			matches++
		}
	}

	fmt.Printf("   ✓ %d/%d peers match (%.1f%% accuracy)\n",
		matches, len(kNearest), float64(matches)/float64(len(kNearest))*100)

	// Verify routing convergence
	fmt.Println("\n11. Verifying Routing Convergence...")

	localDist := kbucket.Xor(localID, targetID)

	validHops := 0
	for _, p := range kNearest {
		pID := kbucket.ConvertPeerID(p)
		pDist := kbucket.Xor(pID, targetID)

		if distLess(pDist, localDist) {
			validHops++
		}
	}

	fmt.Printf("   ✓ %d/%d peers are closer to the target than the current server.\n", validHops, len(kNearest))

	if validHops > 0 {
		fmt.Println("   ✓ SUCCESS: The private lookup returned peers that allow routing to proceed.")
	} else {
		fmt.Println("   ⚠ FAILURE: No progress made towards target.")
	}

	fmt.Println("\n=== Example Complete ===")
	fmt.Printf("\nKey Takeaways:\n")
	fmt.Printf("  • New Strategy Pattern API simplifies PIR configuration\n")
	fmt.Printf("  • Single unified GetBucket() method for all strategies\n")
	fmt.Printf("  • Automatic key generation based on chosen strategy\n")
	fmt.Printf("  • Easy to compare different PIR methods via metadata\n")
}

// findKNearest finds the K nearest peers to a target ID from a list of candidates.
func findKNearest(candidates []peer.ID, target kbucket.ID, k int) []peer.ID {
	if len(candidates) <= k {
		return candidates
	}

	type peerDist struct {
		peer peer.ID
		dist kbucket.ID
	}

	distances := make([]peerDist, len(candidates))
	for i, p := range candidates {
		peerID := kbucket.ConvertPeerID(p)
		dist := kbucket.Xor(peerID, target)
		distances[i] = peerDist{peer: p, dist: dist}
	}

	for i := 0; i < k && i < len(distances); i++ {
		minIdx := i
		for j := i + 1; j < len(distances); j++ {
			if distLess(distances[j].dist, distances[minIdx].dist) {
				minIdx = j
			}
		}
		distances[i], distances[minIdx] = distances[minIdx], distances[i]
	}

	result := make([]peer.ID, k)
	for i := range k {
		result[i] = distances[i].peer
	}

	return result
}

// distLess returns true if a < b in the XOR keyspace
func distLess(a, b kbucket.ID) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func formatSize(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
