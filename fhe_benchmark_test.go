//go:build openfhe

package kbucket

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	"github.com/stretchr/testify/require"

	ma "github.com/multiformats/go-multiaddr"
)

// generateLargeMultiaddrs creates multiple multiaddrs totaling at least 1000 bytes per peer
// This gives more realistic bandwidth measurements for FHE PIR
func generateLargeMultiaddrs(peerIndex int) []ma.Multiaddr {
	addrs := make([]ma.Multiaddr, 0, 6)

	// Create 6 different addresses (mix of protocols) - realistic for most peers
	// This gives ~600-800 bytes per peer, allowing multiple peers to fit in 8KB stride
	for i := 0; i < 6; i++ {
		var addr ma.Multiaddr
		var err error

		switch i % 5 {
		case 0: // IPv4 TCP
			addr, err = ma.NewMultiaddr(fmt.Sprintf("/ip4/192.168.%d.%d/tcp/%d",
				(peerIndex+i)/256, (peerIndex+i)%256, 10000+peerIndex*20+i))
		case 1: // IPv6 TCP
			addr, err = ma.NewMultiaddr(fmt.Sprintf("/ip6/2001:db8::%x/tcp/%d",
				peerIndex*20+i, 20000+peerIndex*20+i))
		case 2: // QUIC
			addr, err = ma.NewMultiaddr(fmt.Sprintf("/ip4/10.0.%d.%d/udp/%d/quic",
				(peerIndex+i)/256, (peerIndex+i)%256, 30000+peerIndex*20+i))
		case 3: // WebSocket
			addr, err = ma.NewMultiaddr(fmt.Sprintf("/ip4/172.16.%d.%d/tcp/%d/ws",
				(peerIndex+i)/256, (peerIndex+i)%256, 40000+peerIndex*20+i))
		case 4: // WebRTC
			addr, err = ma.NewMultiaddr(fmt.Sprintf("/ip4/192.0.2.%d/udp/%d/webrtc",
				(peerIndex+i)%256, 50000+peerIndex*20+i))
		}

		if err == nil {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

// BenchmarkSetup holds the pre-initialized routing table and FHE context
// for benchmark tests to avoid measuring setup time
type BenchmarkSetup struct {
	rt         *RoutingTable
	fheCtx     *FHEContext
	localID    ID
	targetID   ID
	targetCPL  int
	peerCount  int
	bucketInfo BucketDistribution
}

// BucketDistribution holds information about the routing table structure
type BucketDistribution struct {
	BucketCount   int
	MaxCPL        int
	AvgBucketLen  float64
	TotalPeers    int
	BucketLengths []int
}

// setupBenchmarkNetwork creates a routing table with the specified number of peers
func setupBenchmarkNetwork(b *testing.B, peerCount int) *BenchmarkSetup {
	b.Helper()

	// Create FHE context
	fheCtx, err := NewFHEContext()
	require.NoError(b, err)
	err = fheCtx.GenerateKeys()
	require.NoError(b, err)

	// Create routing table
	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(b, err)

	rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)
	require.NoError(b, err)
	rt.EnableFHE(fheCtx)

	// Add peers to the routing table
	addedCount := 0
	for i := 0; i < peerCount*2 && addedCount < peerCount; i++ {
		p := test.RandPeerIDFatal(b)
		// Generate large multiaddrs (20 addresses totaling ~1000+ bytes)
		addrs := generateLargeMultiaddrs(i)

		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, []ma.Multiaddr{testAddr}, true, false); added {
			addedCount++
		}
	}

	// Get bucket distribution info
	rt.tabLock.RLock()
	bucketInfo := BucketDistribution{
		BucketCount:   len(rt.buckets),
		TotalPeers:    rt.Size(),
		BucketLengths: make([]int, len(rt.buckets)),
	}

	totalLen := 0
	maxCPL := 0
	for i, bucket := range rt.buckets {
		bucketLen := bucket.len()
		bucketInfo.BucketLengths[i] = bucketLen
		totalLen += bucketLen
		if bucketLen > 0 {
			maxCPL = i
		}
	}
	rt.tabLock.RUnlock()

	bucketInfo.MaxCPL = maxCPL
	if bucketInfo.BucketCount > 0 {
		bucketInfo.AvgBucketLen = float64(totalLen) / float64(bucketInfo.BucketCount)
	}

	// Select a random target for queries
	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)
	targetCPL := CommonPrefixLen(targetID, localID)

	return &BenchmarkSetup{
		rt:         rt,
		fheCtx:     fheCtx,
		localID:    localID,
		targetID:   targetID,
		targetCPL:  targetCPL,
		peerCount:  addedCount,
		bucketInfo: bucketInfo,
	}
}

// Cleanup releases resources from benchmark setup
func (s *BenchmarkSetup) Cleanup() {
	if s.fheCtx != nil {
		s.fheCtx.Close()
	}
}

// benchmarkFHEPIRQuery performs a single FHE PIR query and measures components
func benchmarkFHEPIRQuery(b *testing.B, setup *BenchmarkSetup) {
	b.Helper()

	var queryCreationTime time.Duration
	var pirComputeTime time.Duration
	var decryptionTime time.Duration
	var responseBytes int64
	var resultPeerCount int64

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Measure query vector creation (client-side encryption)
		start := time.Now()
		queryVec, err := setup.fheCtx.CreateQueryVector(setup.targetCPL)
		queryCreationTime += time.Since(start)
		require.NoError(b, err)

		// Measure PIR computation (server-side homomorphic operations)
		start = time.Now()
		rt := setup.rt
		ps, _ := pstoremem.NewPeerstore()

		// Add addresses to peerstore for the test
		rt.tabLock.RLock()
		for _, bucket := range rt.buckets {
			for _, pInfo := range bucket.peers() {
				addr, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000))
				ps.AddAddrs(pInfo.Id, []ma.Multiaddr{addr}, time.Hour)
			}
		}
		rt.tabLock.RUnlock()

		encryptedResponse, err := rt.GetBucketPIR(queryVec)
		pirComputeTime += time.Since(start)
		require.NoError(b, err)

		// Measure decryption (client-side)
		start = time.Now()
		connectablePeers, err := setup.fheCtx.DecryptConnectablePeers(encryptedResponse)
		decryptionTime += time.Since(start)
		require.NoError(b, err)

		resultPeerCount += int64(len(connectablePeers))

		// Cleanup
		encryptedResponse.Close()
		for _, ct := range queryVec {
			ct.Close()
		}
	}

	b.StopTimer()

	// Report detailed metrics
	b.ReportMetric(float64(queryCreationTime.Milliseconds())/float64(b.N), "ms/query_creation")
	b.ReportMetric(float64(pirComputeTime.Milliseconds())/float64(b.N), "ms/pir_compute")
	b.ReportMetric(float64(decryptionTime.Milliseconds())/float64(b.N), "ms/decryption")
	b.ReportMetric(float64(queryCreationTime.Milliseconds()+pirComputeTime.Milliseconds()+decryptionTime.Milliseconds())/float64(b.N), "ms/total")
	b.ReportMetric(float64(resultPeerCount)/float64(b.N), "peers/result")
	b.ReportMetric(float64(setup.bucketInfo.BucketCount), "buckets")
	b.ReportMetric(float64(setup.bucketInfo.MaxCPL), "max_cpl")
	b.ReportMetric(float64(responseBytes)/float64(b.N), "bytes/response")
}

// Benchmark traditional NearestPeers for comparison
func benchmarkTraditionalQuery(b *testing.B, setup *BenchmarkSetup) float64 {
	b.Helper()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		_ = setup.rt.NearestPeers(setup.targetID, 20)
	}
	elapsed := time.Since(start)

	return float64(elapsed.Nanoseconds()) / float64(b.N)
}

// BenchmarkFHEPIR_NetworkSize_100 benchmarks FHE PIR with 100 peers
func BenchmarkFHEPIR_NetworkSize_100(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 100)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQuery(b, setup)
}

// BenchmarkFHEPIR_NetworkSize_1K benchmarks FHE PIR with 1,000 peers
func BenchmarkFHEPIR_NetworkSize_1K(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 1000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQuery(b, setup)
}

// BenchmarkFHEPIR_NetworkSize_10K benchmarks FHE PIR with 10,000 peers
func BenchmarkFHEPIR_NetworkSize_10K(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 10000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQuery(b, setup)
}

// BenchmarkFHEPIR_NetworkSize_100K benchmarks FHE PIR with 100,000 peers
func BenchmarkFHEPIR_NetworkSize_100K(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 100000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQuery(b, setup)
}

// BenchmarkFHEPIR_NetworkSize_1M benchmarks FHE PIR with 1,000,000 peers
func BenchmarkFHEPIR_NetworkSize_1M(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 1000000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQuery(b, setup)
}

// BenchmarkTraditional_NetworkSize_100 benchmarks traditional queries with 100 peers
func BenchmarkTraditional_NetworkSize_100(b *testing.B) {
	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, _ := pstoremem.NewPeerstore()
	rt, _ := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)

	for i := 0; i < 100; i++ {
		p := test.RandPeerIDFatal(b)
		rt.TryAddPeer(p, []ma.Multiaddr{testAddr}, true, false)
	}

	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rt.NearestPeers(targetID, 20)
	}
}

// BenchmarkTraditional_NetworkSize_1K benchmarks traditional queries with 1,000 peers
func BenchmarkTraditional_NetworkSize_1K(b *testing.B) {
	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, _ := pstoremem.NewPeerstore()
	rt, _ := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)

	for i := 0; i < 1000*2; i++ {
		p := test.RandPeerIDFatal(b)
		rt.TryAddPeer(p, []ma.Multiaddr{testAddr}, true, false)
	}

	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rt.NearestPeers(targetID, 20)
	}
}

// BenchmarkTraditional_NetworkSize_10K benchmarks traditional queries with 10,000 peers
func BenchmarkTraditional_NetworkSize_10K(b *testing.B) {
	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, _ := pstoremem.NewPeerstore()
	rt, _ := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)

	for i := 0; i < 10000*2; i++ {
		p := test.RandPeerIDFatal(b)
		rt.TryAddPeer(p, []ma.Multiaddr{testAddr}, true, false)
	}

	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rt.NearestPeers(targetID, 20)
	}
}

// TestBucketDistribution analyzes how peers distribute across buckets
// for different network sizes
func TestBucketDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping distribution analysis in short mode")
	}

	sizes := []int{100, 1000, 10000, 100000}

	fmt.Println("\n=== Bucket Distribution Analysis ===")
	fmt.Println("Network Size | Buckets | Max CPL | Avg Bucket Size | Peers Added")
	fmt.Println("-------------|---------|---------|-----------------|------------")

	for _, size := range sizes {
		local := test.RandPeerIDFatal(t)
		localID := ConvertPeerID(local)
		ps, err := pstoremem.NewPeerstore()
		require.NoError(t, err)

		rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)
		require.NoError(t, err)

		// Add peers
		addedCount := 0
		for i := 0; i < size*2 && addedCount < size; i++ {
			p := test.RandPeerIDFatal(t)
			// Generate large multiaddrs (20 addresses totaling ~1000+ bytes)
			addrs := generateLargeMultiaddrs(i)

			ps.AddAddrs(p, addrs, time.Hour)
			if added, _ := rt.TryAddPeer(p, []ma.Multiaddr{testAddr}, true, false); added {
				addedCount++
			}
		}

		// Analyze distribution
		rt.tabLock.RLock()
		bucketCount := len(rt.buckets)
		maxCPL := 0
		totalLen := 0

		for i, bucket := range rt.buckets {
			bucketLen := bucket.len()
			totalLen += bucketLen
			if bucketLen > 0 {
				maxCPL = i
			}
		}
		rt.tabLock.RUnlock()

		avgBucketSize := 0.0
		if bucketCount > 0 {
			avgBucketSize = float64(totalLen) / float64(bucketCount)
		}

		fmt.Printf("%12d | %7d | %7d | %15.2f | %11d\n",
			size, bucketCount, maxCPL, avgBucketSize, addedCount)
	}

	fmt.Println("\nNote: Max CPL should grow logarithmically with network size")
	fmt.Println("Expected: ~log2(N) buckets for N peers")
}

// TestMemoryUsage measures memory consumption for different network sizes
func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	sizes := []int{100, 1000, 10000}

	fmt.Println("\n=== Memory Usage Analysis ===")
	fmt.Println("Network Size | Before (MB) | After (MB) | Delta (MB) | MB/Peer")
	fmt.Println("-------------|-------------|------------|------------|--------")

	for _, size := range sizes {
		runtime.GC()
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)

		local := test.RandPeerIDFatal(t)
		localID := ConvertPeerID(local)
		ps, _ := pstoremem.NewPeerstore()
		rt, _ := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)

		for i := 0; i < size*2; i++ {
			p := test.RandPeerIDFatal(t)
			rt.TryAddPeer(p, []ma.Multiaddr{testAddr}, true, false)
		}

		runtime.GC()
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)

		before := float64(m1.Alloc) / 1024 / 1024
		after := float64(m2.Alloc) / 1024 / 1024
		delta := after - before
		perPeer := delta / float64(size)

		fmt.Printf("%12d | %11.2f | %10.2f | %10.2f | %7.4f\n",
			size, before, after, delta, perPeer)
	}
}

// ============================================================================
// PACKED PIR BENCHMARKS (Optimized Single Ciphertext Approach)
// ============================================================================

// setupBenchmarkNetworkPacked creates a routing table with rotation keys enabled
func setupBenchmarkNetworkPacked(b *testing.B, peerCount int) *BenchmarkSetup {
	b.Helper()

	// Create FHE context with rotation keys
	fheCtx, err := NewFHEContext()
	require.NoError(b, err)
	err = fheCtx.GenerateKeysWithRotation()
	require.NoError(b, err)

	// Create routing table
	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, err := pstoremem.NewPeerstore()
	require.NoError(b, err)

	rt, err := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)
	require.NoError(b, err)
	rt.EnableFHE(fheCtx)

	// Add peers to the routing table
	addedCount := 0
	for i := 0; i < peerCount*2 && addedCount < peerCount; i++ {
		p := test.RandPeerIDFatal(b)
		// Generate large multiaddrs (20 addresses totaling ~1000+ bytes)
		addrs := generateLargeMultiaddrs(i)

		ps.AddAddrs(p, addrs, time.Hour)
		if added, _ := rt.TryAddPeer(p, []ma.Multiaddr{testAddr}, true, false); added {
			addedCount++
		}
	}

	// Get bucket distribution info
	rt.tabLock.RLock()
	bucketInfo := BucketDistribution{
		BucketCount:   len(rt.buckets),
		TotalPeers:    rt.Size(),
		BucketLengths: make([]int, len(rt.buckets)),
	}

	totalLen := 0
	maxCPL := 0
	for i, bucket := range rt.buckets {
		bucketLen := bucket.len()
		bucketInfo.BucketLengths[i] = bucketLen
		totalLen += bucketLen
		if bucketLen > 0 {
			maxCPL = i
		}
	}
	rt.tabLock.RUnlock()

	bucketInfo.MaxCPL = maxCPL
	if bucketInfo.BucketCount > 0 {
		bucketInfo.AvgBucketLen = float64(totalLen) / float64(bucketInfo.BucketCount)
	}

	// Select a random target for queries
	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)
	targetCPL := CommonPrefixLen(targetID, localID)

	return &BenchmarkSetup{
		rt:         rt,
		fheCtx:     fheCtx,
		localID:    localID,
		targetID:   targetID,
		targetCPL:  targetCPL,
		peerCount:  addedCount,
		bucketInfo: bucketInfo,
	}
}

// benchmarkFHEPIRQueryPacked performs a single FHE PIR query using packed approach
func benchmarkFHEPIRQueryPacked(b *testing.B, setup *BenchmarkSetup) {
	b.Helper()

	var queryCreationTime time.Duration
	var pirComputeTime time.Duration
	var decryptionTime time.Duration
	var resultPeerCount int64

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Measure query vector creation (client-side encryption) - PACKED VERSION
		start := time.Now()
		queryCt, err := setup.fheCtx.CreateQueryVectorPacked(setup.targetCPL)
		queryCreationTime += time.Since(start)
		require.NoError(b, err)

		// Measure PIR computation (server-side homomorphic operations) - PACKED VERSION
		start = time.Now()
		rt := setup.rt
		ps, _ := pstoremem.NewPeerstore()

		// Add addresses to peerstore for the test
		rt.tabLock.RLock()
		for _, bucket := range rt.buckets {
			for _, pInfo := range bucket.peers() {
				addr, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000))
				ps.AddAddrs(pInfo.Id, []ma.Multiaddr{addr}, time.Hour)
			}
		}
		rt.tabLock.RUnlock()

		encryptedResponse, err := rt.GetBucketPIRPacked(queryCt)
		pirComputeTime += time.Since(start)
		require.NoError(b, err)

		// Measure decryption (client-side) - Same as original
		start = time.Now()
		connectablePeers, err := setup.fheCtx.DecryptConnectablePeers(encryptedResponse)
		decryptionTime += time.Since(start)
		require.NoError(b, err)

		resultPeerCount += int64(len(connectablePeers))

		// Cleanup
		encryptedResponse.Close()
		queryCt.Close()
	}

	b.StopTimer()

	// Report detailed metrics
	b.ReportMetric(float64(queryCreationTime.Milliseconds())/float64(b.N), "ms/query_creation")
	b.ReportMetric(float64(pirComputeTime.Milliseconds())/float64(b.N), "ms/pir_compute")
	b.ReportMetric(float64(decryptionTime.Milliseconds())/float64(b.N), "ms/decryption")
	b.ReportMetric(float64(queryCreationTime.Milliseconds()+pirComputeTime.Milliseconds()+decryptionTime.Milliseconds())/float64(b.N), "ms/total")
	b.ReportMetric(float64(resultPeerCount)/float64(b.N), "peers/result")
	b.ReportMetric(float64(setup.bucketInfo.BucketCount), "buckets")
	b.ReportMetric(float64(setup.bucketInfo.MaxCPL), "max_cpl")
}

// BenchmarkFHEPIRPacked_NetworkSize_100 benchmarks packed FHE PIR with 100 peers
func BenchmarkFHEPIRPacked_NetworkSize_100(b *testing.B) {
	setup := setupBenchmarkNetworkPacked(b, 100)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PACKED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPacked(b, setup)
}

// BenchmarkFHEPIRPacked_NetworkSize_1K benchmarks packed FHE PIR with 1,000 peers
func BenchmarkFHEPIRPacked_NetworkSize_1K(b *testing.B) {
	setup := setupBenchmarkNetworkPacked(b, 1000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PACKED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPacked(b, setup)
}

// BenchmarkFHEPIRPacked_NetworkSize_10K benchmarks packed FHE PIR with 10,000 peers
func BenchmarkFHEPIRPacked_NetworkSize_10K(b *testing.B) {
	setup := setupBenchmarkNetworkPacked(b, 10000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PACKED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPacked(b, setup)
}

// BenchmarkFHEPIRPacked_NetworkSize_100K benchmarks packed FHE PIR with 100,000 peers
func BenchmarkFHEPIRPacked_NetworkSize_100K(b *testing.B) {
	setup := setupBenchmarkNetworkPacked(b, 100000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PACKED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPacked(b, setup)
}

// BenchmarkFHEPIRPacked_NetworkSize_1M benchmarks packed FHE PIR with 1,000,000 peers
func BenchmarkFHEPIRPacked_NetworkSize_1M(b *testing.B) {
	setup := setupBenchmarkNetworkPacked(b, 1000000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PACKED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPacked(b, setup)
}

// ============================================================================
// PAGED PIR BENCHMARKS
// ============================================================================

// BenchmarkFHEPIRPaged_NetworkSize_100 benchmarks paged FHE PIR with 100 peers
func BenchmarkFHEPIRPaged_NetworkSize_100(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 100)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PAGED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPaged(b, setup)
}

// BenchmarkFHEPIRPaged_NetworkSize_1K benchmarks paged FHE PIR with 1,000 peers
func BenchmarkFHEPIRPaged_NetworkSize_1K(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 1000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PAGED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPaged(b, setup)
}

// BenchmarkFHEPIRPaged_NetworkSize_10K benchmarks paged FHE PIR with 10,000 peers
func BenchmarkFHEPIRPaged_NetworkSize_10K(b *testing.B) {
	setup := setupBenchmarkNetwork(b, 10000)
	defer setup.Cleanup()

	b.Logf("Network: %d peers, %d buckets, max CPL: %d (PAGED)",
		setup.bucketInfo.TotalPeers, setup.bucketInfo.BucketCount, setup.bucketInfo.MaxCPL)

	benchmarkFHEPIRQueryPaged(b, setup)
}

// benchmarkFHEPIRQueryPaged runs the benchmark for paged PIR queries
func benchmarkFHEPIRQueryPaged(b *testing.B, setup *BenchmarkSetup) {
	b.Helper()

	var queryCreationTime time.Duration
	var pirComputeTime time.Duration
	var decryptionTime time.Duration
	var numCiphertexts int

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Measure query vector creation (client-side encryption)
		start := time.Now()
		queryVector, err := setup.fheCtx.CreateQueryVectorPaged(setup.targetCPL)
		queryCreationTime += time.Since(start)
		require.NoError(b, err)
		numCiphertexts = len(queryVector)

		// Measure PIR computation (server-side homomorphic operations)
		start = time.Now()
		rt := setup.rt
		ps, _ := pstoremem.NewPeerstore()

		// Add addresses to peerstore for the test
		rt.tabLock.RLock()
		for idx, bucket := range rt.buckets {
			for _, pInfo := range bucket.peers() {
				// Use large multiaddrs for realistic bandwidth testing
				addrs := generateLargeMultiaddrs(idx * 1000)
				ps.AddAddrs(pInfo.Id, addrs, time.Hour)
			}
		}
		rt.tabLock.RUnlock()

		encryptedResponse, err := rt.GetBucketPIRPaged(queryVector)
		pirComputeTime += time.Since(start)
		require.NoError(b, err)

		// Measure decryption (client-side)
		start = time.Now()
		connectablePeers, err := setup.fheCtx.DecryptConnectablePeersPaged(encryptedResponse, setup.targetCPL)
		decryptionTime += time.Since(start)
		require.NoError(b, err)

		// Cleanup
		for _, ct := range queryVector {
			ct.Close()
		}
		encryptedResponse.Close()
		_ = connectablePeers
	}

	b.StopTimer()

	// Calculate averages
	avgQueryCreation := queryCreationTime / time.Duration(b.N)
	avgPIRCompute := pirComputeTime / time.Duration(b.N)
	avgDecryption := decryptionTime / time.Duration(b.N)
	avgTotal := avgQueryCreation + avgPIRCompute + avgDecryption

	b.ReportMetric(float64(setup.bucketInfo.BucketCount), "buckets")
	b.ReportMetric(float64(numCiphertexts), "ciphertexts")
	b.ReportMetric(float64(setup.bucketInfo.MaxCPL), "max_cpl")
	b.ReportMetric(avgDecryption.Seconds()*1000, "ms/decryption")
	b.ReportMetric(avgPIRCompute.Seconds()*1000, "ms/pir_compute")
	b.ReportMetric(avgQueryCreation.Seconds()*1000, "ms/query_creation")
	b.ReportMetric(avgTotal.Seconds()*1000, "ms/total")
}
