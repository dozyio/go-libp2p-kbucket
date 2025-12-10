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
	fmt.Println("=== FHE-Based Private Routing Table Lookup (Greedy Adaptive PIR With Normalized Routing Table) ===")

	bucketSize := 20

	// Step 1: Set up FHE context
	fmt.Println("1. Setting up FHE context...")
	fheCtx, err := kbucket.NewFHEContext()
	if err != nil {
		log.Fatalf("Failed to create FHE context: %v", err)
	}
	defer fheCtx.Close()

	// naive key rotations
	// err = fheCtx.GenerateKeysWithRotation()
	// use power-of-two keys
	err = fheCtx.GenerateKeysPowerOfTwo()
	// single unit keys
	// err = fheCtx.GenerateKeysMinimal()
	if err != nil {
		log.Fatalf("Failed to generate FHE keys: %v", err)
	}
	fmt.Println("   ✓ FHE context created with STD128 security")
	fmt.Println("   ✓ Rotation keys generated for Greedy Adaptive PIR")

	ccBytes, _ := openfhe.SerializeCryptoContextToBytes(fheCtx.CC)
	fmt.Printf("Context (Params):     %s\n", formatSize(len(ccBytes)))

	pkBytes, _ := openfhe.SerializePublicKeyToBytes(fheCtx.KP)
	fmt.Printf("Public Key:           %s\n", formatSize(len(pkBytes)))

	skBytes, _ := openfhe.SerializePrivateKeyToBytes(fheCtx.KP)
	fmt.Printf("Private Key:          %s\n", formatSize(len(skBytes)))

	multBytes, _ := openfhe.SerializeEvalMultKeyToBytes(fheCtx.CC, "")
	fmt.Printf("Relinearization Key:  %s\n", formatSize(len(multBytes)))

	rotBytes, _ := openfhe.SerializeEvalAutomorphismKeyToBytes(fheCtx.CC, "")
	fmt.Printf("Rotation Keys (Total):%s\n", formatSize(len(rotBytes)))

	// Step 2: Create server's routing table
	fmt.Println("\n2. Creating server routing table...")
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
	peers := make([]peer.ID, 0, 100000)

	// Add peers for CPL 0-15 to force bucket splitting
	// Each CPL gets multiple peers to fill buckets and trigger splits
	for cpl := range 16 {
		peersForCPL := bucketSize // Add k peers per CPL level
		for i := range peersForCPL {
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
	rt.Print()

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
	// Calculate which bucket will be used (same logic as NearestPeers)
	lookupCPL := kbucket.CommonPrefixLen(targetID, localID)
	fmt.Printf("   Bucket index used: %d (based on CPL between target and local node)\n", lookupCPL)
	start := time.Now()
	traditionalPeers := rt.NearestPeers(targetID, 20)
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
	responseCts, err := rt.GetBucketPIRGreedyAdaptiveNormalized(queryCt, ps)
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
	kNearest := findKNearest(bucketPeerIDs, targetID, 20)
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
	matches := 0
	fmt.Println("\n8. Verifying similar results...")

	// Create a map for O(1) lookups
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

	// Verify correctness
	fmt.Println("\n8. Verifying Routing Convergence...")

	// Calculate the distance from Local Node to Target
	localDist := kbucket.Xor(localID, targetID)

	validHops := 0
	for _, p := range kNearest {
		// Calculate distance from Retrieved Peer to Target
		pID := kbucket.ConvertPeerID(p)
		pDist := kbucket.Xor(pID, targetID)

		// Check if the Retrieved Peer is strictly closer than Local Node
		if distLess(pDist, localDist) {
			validHops++
		}
	}

	fmt.Printf("   ✓ %d/%d peers are closer to the target than the current server.\n", validHops, len(kNearest))

	if validHops > 0 {
		fmt.Println("   ✓ SUCCESS: The private lookup returned peers that allow routing to proceed.")
	} else {
		// Note: In a very sparse network or edge case, 0 is theoretically possible
		// if the server itself is the closest node, but unlikely with 20 peers.
		fmt.Println("   ⚠ FAILURE: No progress made towards target.")
	}
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
