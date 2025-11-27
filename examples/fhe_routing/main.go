//go:build openfhe

package main

import (
	"fmt"
	"log"
	"time"

	kbucket "github.com/libp2p/go-libp2p-kbucket"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	ma "github.com/multiformats/go-multiaddr"
)

// This example demonstrates privacy-preserving routing table lookups using FHE
// with the Greedy Adaptive PIR mechanism.
//
// Scenario:
//   - Server hosts a routing table with multiple peers
//   - Client wants to find peers close to a target ID
//   - Client doesn't want to reveal the target ID to the server
//   - Server uses Greedy Adaptive PIR to return the bucket without learning the target
//   - Client filters locally to find the K-nearest peers
//
// The Greedy Adaptive method:
//   - Uses a single packed ciphertext query (not 24 separate ciphertexts)
//   - Adapts to bucket size (returns 1+ ciphertexts based on max bucket size)
//   - Uses "Destructive Summation" to ensure only 1 bucket is retrievable
//   - Provides better performance and security than basic PIR
//
// To run this example:
//   1. Install OpenFHE C++ library: https://github.com/openfheorg/openfhe-development
//   2. Build with: go build -tags openfhe
//   3. Run: ./fhe_routing

func main() {
	fmt.Println("=== FHE-Based Private Routing Table Lookup (Greedy Adaptive PIR) ===\n")

	// Step 1: Set up FHE context
	fmt.Println("1. Setting up FHE context...")
	fheCtx, err := kbucket.NewFHEContext()
	if err != nil {
		log.Fatalf("Failed to create FHE context: %v", err)
	}
	defer fheCtx.Close()

	err = fheCtx.GenerateKeysWithRotation()
	if err != nil {
		log.Fatalf("Failed to generate FHE keys: %v", err)
	}
	fmt.Println("   ✓ FHE context created with STD128 security")
	fmt.Println("   ✓ Rotation keys generated for Greedy Adaptive PIR")

	// Step 2: Create server's routing table
	fmt.Println("\n2. Creating server routing table...")
	localPeer := test.RandPeerIDFatal(nil)
	localID := kbucket.ConvertPeerID(localPeer)

	ps, err := pstoremem.NewPeerstore()
	if err != nil {
		log.Fatalf("Failed to create peerstore: %v", err)
	}

	rt, err := kbucket.NewRoutingTable(
		20,            // bucket size
		localID,       // local node ID
		time.Hour,     // max latency
		ps,            // peerstore (metrics)
		100*time.Hour, // usefulness grace period
		nil,           // peer diversity filter
	)
	if err != nil {
		log.Fatalf("Failed to create routing table: %v", err)
	}

	// Enable FHE for this routing table
	rt.EnableFHE(fheCtx)
	fmt.Printf("   ✓ Routing table created for peer %s\n", localPeer.String()[:16]+"...")
	fmt.Println("   ✓ FHE enabled with Greedy Adaptive PIR")

	// Step 3: Populate routing table with peers
	fmt.Println("\n3. Populating routing table with peers...")

	// Strategy: Add peers across different CPL ranges to create multiple buckets
	// This ensures the routing table splits into more buckets, allowing more total peers
	peers := make([]peer.ID, 0, 200)

	// Add peers for CPL 0-15 to force bucket splitting
	// Each CPL gets multiple peers to fill buckets and trigger splits
	for cpl := 0; cpl < 16; cpl++ {
		peersForCPL := 25 // Add 25 peers per CPL level
		for i := 0; i < peersForCPL; i++ {
			// Generate a peer with specific CPL to local node
			p, err := kbucket.GenRandPeerIDWithCPL(localID, uint(cpl))
			if err != nil {
				continue
			}

			// Add multiaddr for this peer to peerstore
			addrStr := fmt.Sprintf("/ip4/127.0.0.%d/tcp/%d", cpl+1, 10000+i)
			addr, err := ma.NewMultiaddr(addrStr)
			if err != nil {
				continue
			}
			ps.AddAddrs(p, []ma.Multiaddr{addr}, time.Hour)

			// Try to add peer to routing table
			// - queryPeer=true: this is a peer we queried (sets LastUsefulAt)
			// - isReplaceable=true: allows this peer to be replaced if bucket is full
			// Note: Buckets split automatically when the LAST bucket becomes full
			added, err := rt.TryAddPeer(p, true, true)
			if err != nil {
				// Silently skip peers that can't be added
				continue
			}
			if added {
				peers = append(peers, p)
			}
		}
	}

	fmt.Printf("   ✓ Added %d peers to routing table\n", rt.Size())
	fmt.Printf("   ✓ Routing table will auto-expand as needed (bucket splitting)\n")

	// Step 4: Client creates a target ID (what they're searching for)
	fmt.Println("\n4. Client selects target peer to search for...")
	if len(peers) == 0 {
		log.Fatalf("No peers were added to the routing table")
	}
	targetPeer := peers[len(peers)/2] // Pick a peer in the middle
	targetID := kbucket.ConvertPeerID(targetPeer)
	targetCPL := kbucket.CommonPrefixLen(localID, targetID)
	fmt.Printf("   Target peer: %s\n", targetPeer.String()[:16]+"...")
	fmt.Printf("   Target CPL:  %d\n", targetCPL)

	// Step 5: Traditional (non-private) lookup for comparison
	fmt.Println("\n5. Traditional lookup (server learns target)...")
	start := time.Now()
	traditionalPeers := rt.NearestPeers(targetID, 10)
	traditionalDuration := time.Since(start)
	fmt.Printf("   Found %d peers in %v\n", len(traditionalPeers), traditionalDuration)

	// Step 6: FHE-based private lookup using Greedy Adaptive PIR
	fmt.Println("\n6. FHE-based private lookup (Greedy Adaptive PIR)...")

	// Client encrypts the query as a single packed ciphertext
	fmt.Println("   a) Client creates encrypted query vector...")
	encryptStart := time.Now()
	queryCt, err := fheCtx.CreateQueryVectorGreedy(targetCPL)
	if err != nil {
		log.Fatalf("Failed to create query vector: %v", err)
	}
	defer queryCt.Close()
	encryptDuration := time.Since(encryptStart)
	fmt.Printf("      ✓ Query encryption took %v\n", encryptDuration)
	fmt.Printf("      ✓ Single packed ciphertext\n")

	// Server processes the encrypted query
	fmt.Println("   b) Server processes encrypted query...")
	queryStart := time.Now()
	responseCts, err := rt.GetBucketPIRGreedyAdaptive(queryCt, ps)
	if err != nil {
		log.Fatalf("Failed to get bucket: %v", err)
	}
	defer func() {
		for _, ct := range responseCts {
			ct.Close()
		}
	}()
	queryDuration := time.Since(queryStart)
	fmt.Printf("      ✓ Server computed PIR response in %v\n", queryDuration)
	fmt.Printf("      ✓ Returned %d ciphertext(s) (adaptive to bucket size)\n", len(responseCts))
	fmt.Println("      ✓ Server never learned the target ID!")

	// Client decrypts the response
	fmt.Println("   c) Client decrypts response...")
	decryptStart := time.Now()
	bucketPeers, err := fheCtx.DecryptGreedyAdaptiveResponse(responseCts)
	if err != nil {
		log.Fatalf("Failed to decrypt response: %v", err)
	}
	decryptDuration := time.Since(decryptStart)
	fmt.Printf("      ✓ Decryption took %v\n", decryptDuration)
	fmt.Printf("      ✓ Retrieved %d peers from bucket\n", len(bucketPeers))

	// Client filters locally
	fmt.Println("   d) Client filters locally to find K-nearest...")
	// Convert ConnectablePeers to peer.IDs for filtering
	bucketPeerIDs := make([]peer.ID, len(bucketPeers))
	for i, cp := range bucketPeers {
		bucketPeerIDs[i] = cp.ID
	}
	kNearest := findKNearest(bucketPeerIDs, targetID, 10)
	fmt.Printf("      ✓ Found %d nearest peers\n", len(kNearest))

	// Step 7: Compare results
	fmt.Println("\n7. Comparing results...")
	totalFHETime := encryptDuration + queryDuration + decryptDuration
	fmt.Printf("   Traditional time: %v\n", traditionalDuration)
	fmt.Printf("   FHE time:         %v (%.1fx slower)\n",
		totalFHETime, float64(totalFHETime)/float64(traditionalDuration))
	fmt.Printf("   \n")
	fmt.Printf("   Breakdown:\n")
	fmt.Printf("     - Query creation:  %v\n", encryptDuration)
	fmt.Printf("     - Server PIR:      %v\n", queryDuration)
	fmt.Printf("     - Client decrypt:  %v\n", decryptDuration)
	fmt.Printf("   \n")
	fmt.Printf("   Privacy gain: Target ID completely hidden from server\n")
	fmt.Printf("   Security:     Destructive Summation ensures only 1 bucket retrievable\n")

	// Verify correctness
	fmt.Println("\n8. Verifying correctness...")
	if len(kNearest) != len(traditionalPeers) {
		fmt.Printf("   ⚠ Different result sizes: FHE=%d, Traditional=%d\n",
			len(kNearest), len(traditionalPeers))
	} else {
		matches := 0
		for i := range kNearest {
			if kNearest[i] == traditionalPeers[i] {
				matches++
			}
		}
		fmt.Printf("   ✓ %d/%d peers match (%.1f%% accuracy)\n",
			matches, len(kNearest), float64(matches)/float64(len(kNearest))*100)
	}

	fmt.Println("\n=== Example Complete ===")
	fmt.Println("\nKey Takeaways:")
	fmt.Println("  • Greedy Adaptive PIR uses single packed ciphertext (not 24)")
	fmt.Println("  • Adapts response size to bucket capacity (1+ ciphertexts)")
	fmt.Println("  • Server never learns the target peer ID")
	fmt.Println("  • Destructive Summation ensures only 1 bucket is retrievable")
	fmt.Println("  • Client can filter results locally for exact K-nearest")
	fmt.Println("  • Performance is excellent for privacy-sensitive applications")
}

// findKNearest finds the K nearest peers to a target ID from a list of candidates.
// This would typically be done on the client side after receiving the bucket.
func findKNearest(candidates []peer.ID, target kbucket.ID, k int) []peer.ID {
	if len(candidates) <= k {
		return candidates
	}

	// Sort by XOR distance to target
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

	// Simple selection sort for K nearest
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
	for i := 0; i < k; i++ {
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
