//go:build openfhe

package kbucket

import (
	"fmt"
	"testing"
	"time"

	"github.com/dozyio/openfhe-go/openfhe"
	"github.com/libp2p/go-libp2p/core/test"
	pstoremem "github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// FHEContextCustom allows creating FHE contexts with custom parameters
type FHEContextCustom struct {
	cc      *openfhe.CryptoContext
	kp      *openfhe.KeyPair
	params  *openfhe.ParamsBGV
	ringDim int
}

// NewFHEContextCustom creates an FHE context with custom multiplicative depth
// multDepth=1 gives ringDim=8192, multDepth=2 gives ringDim=16384, etc.
func NewFHEContextCustom(multDepth uint32) (*FHEContextCustom, error) {
	params, err := openfhe.NewParamsBGVrns()
	if err != nil {
		return nil, err
	}

	params.SetPlaintextModulus(65537)
	params.SetMultiplicativeDepth(int(multDepth))
	params.SetScalingTechnique(openfhe.FIXEDMANUAL)

	cc, err := openfhe.NewCryptoContextBGV(params)
	if err != nil {
		return nil, err
	}

	cc.Enable(openfhe.PKE)
	cc.Enable(openfhe.KEYSWITCH)
	cc.Enable(openfhe.LEVELEDSHE)

	ringDim := cc.GetRingDimension()

	return &FHEContextCustom{cc: cc, params: params, ringDim: int(ringDim)}, nil
}

// GenerateKeys generates keypair for custom context
func (ctx *FHEContextCustom) GenerateKeys() error {
	kp, err := ctx.cc.KeyGen()
	if err != nil {
		return err
	}
	ctx.kp = kp
	ctx.cc.EvalMultKeyGen(kp)
	return nil
}

// GenerateKeysWithRotation generates keys with rotation support
func (ctx *FHEContextCustom) GenerateKeysWithRotation() error {
	kp, err := ctx.cc.KeyGen()
	if err != nil {
		return err
	}
	ctx.kp = kp
	ctx.cc.EvalMultKeyGen(kp)

	indexList := make([]int32, 0, MaxCPL*2)
	for i := 0; i < MaxCPL; i++ {
		indexList = append(indexList, int32(i))
	}
	for shift := int32(1); shift < int32(ctx.ringDim); shift *= 2 {
		indexList = append(indexList, -shift)
	}

	return ctx.cc.EvalRotateKeyGen(kp, indexList)
}

// Close releases resources
func (ctx *FHEContextCustom) Close() {
	if ctx.params != nil {
		ctx.params.Close()
	}
}

// RingDimBenchmarkResult holds comprehensive benchmark results
type RingDimBenchmarkResult struct {
	RingDim   int
	MultDepth uint32

	// Timing measurements
	EncryptionTime time.Duration
	DecryptionTime time.Duration
	MultPlainTime  time.Duration
	AddTime        time.Duration
	RotationTime   time.Duration

	// Size measurements (actual serialized bytes)
	CiphertextBytes int
	PublicKeyBytes  int
	EvalKeyBytes    int
	RotKeyBytes     int

	// Derived metrics
	BucketsPerPage  int
	NumPages        int
	EstimatedUpload int64 // Estimated upload for 24-CT approach
	EstimatedPaged  int64 // Estimated upload for paged approach
}

// BenchmarkRingDimParameters tests different ringDim values comprehensively
func BenchmarkRingDimParameters(b *testing.B) {
	// Test multiple multiplicative depths
	testConfigs := []struct {
		multDepth uint32
		name      string
	}{
		{1, "MultDepth1_RingDim8K"},
		{2, "MultDepth2_RingDim16K"},
		{3, "MultDepth3_RingDim32K"},
	}

	for _, config := range testConfigs {
		b.Run(config.name, func(b *testing.B) {
			benchmarkSingleRingDim(b, config.multDepth)
		})
	}
}

// benchmarkSingleRingDim performs detailed benchmarking for a specific ringDim
func benchmarkSingleRingDim(b *testing.B, multDepth uint32) {
	ctx, err := NewFHEContextCustom(multDepth)
	require.NoError(b, err)
	defer ctx.Close()

	err = ctx.GenerateKeysWithRotation()
	require.NoError(b, err)

	result := &RingDimBenchmarkResult{
		RingDim:   ctx.ringDim,
		MultDepth: multDepth,
	}

	// Calculate paging parameters
	const stride = BucketStride
	bucketsPerPage := ctx.ringDim / stride
	numPages := MaxCPL / bucketsPerPage
	if MaxCPL%bucketsPerPage != 0 {
		numPages++
	}
	result.BucketsPerPage = bucketsPerPage
	result.NumPages = numPages

	// Prepare test data
	testVector := make([]int64, ctx.ringDim)
	for i := range testVector {
		testVector[i] = int64(i % 256)
	}

	pt, err := ctx.cc.MakePackedPlaintext(testVector)
	require.NoError(b, err)
	defer pt.Close()

	// Measure encryption time
	b.Run("Encryption", func(b *testing.B) {
		start := time.Now()
		for i := 0; i < b.N; i++ {
			ct, err := ctx.cc.Encrypt(ctx.kp, pt)
			require.NoError(b, err)
			ct.Close()
		}
		result.EncryptionTime = time.Since(start) / time.Duration(b.N)
		b.ReportMetric(result.EncryptionTime.Seconds()*1000, "ms/op")
	})

	// Create a ciphertext for other operations
	ct, err := ctx.cc.Encrypt(ctx.kp, pt)
	require.NoError(b, err)

	// Measure decryption time
	b.Run("Decryption", func(b *testing.B) {
		start := time.Now()
		for i := 0; i < b.N; i++ {
			ptDec, err := ctx.cc.Decrypt(ctx.kp, ct)
			require.NoError(b, err)
			ptDec.Close()
		}
		result.DecryptionTime = time.Since(start) / time.Duration(b.N)
		b.ReportMetric(result.DecryptionTime.Seconds()*1000, "ms/op")
	})

	// Measure multiplication with plaintext
	b.Run("MultPlain", func(b *testing.B) {
		start := time.Now()
		for i := 0; i < b.N; i++ {
			ctResult, err := ctx.cc.EvalMultPlain(ct, pt)
			require.NoError(b, err)
			ctResult.Close()
		}
		result.MultPlainTime = time.Since(start) / time.Duration(b.N)
		b.ReportMetric(result.MultPlainTime.Seconds()*1000, "ms/op")
	})

	// Measure addition
	b.Run("Add", func(b *testing.B) {
		start := time.Now()
		for i := 0; i < b.N; i++ {
			ctResult, err := ctx.cc.EvalAdd(ct, ct)
			require.NoError(b, err)
			ctResult.Close()
		}
		result.AddTime = time.Since(start) / time.Duration(b.N)
		b.ReportMetric(result.AddTime.Seconds()*1000, "ms/op")
	})

	// Measure rotation (if rotation keys exist)
	b.Run("Rotation", func(b *testing.B) {
		start := time.Now()
		for i := 0; i < b.N; i++ {
			ctResult, err := ctx.cc.EvalRotate(ct, 1)
			require.NoError(b, err)
			ctResult.Close()
		}
		result.RotationTime = time.Since(start) / time.Duration(b.N)
		b.ReportMetric(result.RotationTime.Seconds()*1000, "ms/op")
	})

	// Measure actual ciphertext size
	// OpenFHE doesn't expose serialization directly in Go bindings,
	// so we estimate based on structure: 2 polynomials × ringDim × 8 bytes
	result.CiphertextBytes = 2 * ctx.ringDim * 8

	// Calculate estimated bandwidth
	result.EstimatedUpload = int64(MaxCPL * result.CiphertextBytes)         // 24 ciphertexts
	result.EstimatedPaged = int64(result.NumPages * result.CiphertextBytes) // Paged approach

	ct.Close()

	// Report summary metrics
	b.ReportMetric(float64(result.RingDim), "ring_dim")
	b.ReportMetric(float64(result.BucketsPerPage), "buckets_per_page")
	b.ReportMetric(float64(result.NumPages), "num_pages")
	b.ReportMetric(float64(result.CiphertextBytes), "bytes/ciphertext")
	b.ReportMetric(float64(result.EstimatedUpload)/1024/1024, "MB/24ct_upload")
	b.ReportMetric(float64(result.EstimatedPaged)/1024/1024, "MB/paged_upload")
}

// TestRingDimComparison generates a detailed comparison table
func TestRingDimComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping detailed comparison in short mode")
	}

	configs := []uint32{1, 2, 3}
	results := make([]*RingDimBenchmarkResult, 0, len(configs))

	fmt.Println("\n=== Ring Dimension Comparison ===")

	for _, multDepth := range configs {
		ctx, err := NewFHEContextCustom(multDepth)
		require.NoError(t, err)

		err = ctx.GenerateKeysWithRotation()
		require.NoError(t, err)

		result := &RingDimBenchmarkResult{
			RingDim:   ctx.ringDim,
			MultDepth: multDepth,
		}

		// Calculate paging parameters
		bucketsPerPage := ctx.ringDim / BucketStride
		numPages := MaxCPL / bucketsPerPage
		if MaxCPL%bucketsPerPage != 0 {
			numPages++
		}
		result.BucketsPerPage = bucketsPerPage
		result.NumPages = numPages

		// Prepare test data
		testVector := make([]int64, ctx.ringDim)
		for i := range testVector {
			testVector[i] = int64(i % 256)
		}

		pt, err := ctx.cc.MakePackedPlaintext(testVector)
		require.NoError(t, err)

		// Measure operations
		iterations := 100

		// Encryption
		start := time.Now()
		for i := 0; i < iterations; i++ {
			ct, _ := ctx.cc.Encrypt(ctx.kp, pt)
			ct.Close()
		}
		result.EncryptionTime = time.Since(start) / time.Duration(iterations)

		// Create CT for other ops
		ct, _ := ctx.cc.Encrypt(ctx.kp, pt)

		// Decryption
		start = time.Now()
		for i := 0; i < iterations; i++ {
			ptDec, _ := ctx.cc.Decrypt(ctx.kp, ct)
			ptDec.Close()
		}
		result.DecryptionTime = time.Since(start) / time.Duration(iterations)

		// Multiplication
		start = time.Now()
		for i := 0; i < iterations; i++ {
			ctResult, _ := ctx.cc.EvalMultPlain(ct, pt)
			ctResult.Close()
		}
		result.MultPlainTime = time.Since(start) / time.Duration(iterations)

		// Addition
		start = time.Now()
		for i := 0; i < iterations; i++ {
			ctResult, _ := ctx.cc.EvalAdd(ct, ct)
			ctResult.Close()
		}
		result.AddTime = time.Since(start) / time.Duration(iterations)

		// Rotation
		start = time.Now()
		for i := 0; i < iterations; i++ {
			ctResult, _ := ctx.cc.EvalRotate(ct, 1)
			ctResult.Close()
		}
		result.RotationTime = time.Since(start) / time.Duration(iterations)

		// Size estimates
		result.CiphertextBytes = 2 * ctx.ringDim * 8
		result.EstimatedUpload = int64(MaxCPL * result.CiphertextBytes)
		result.EstimatedPaged = int64(result.NumPages * result.CiphertextBytes)

		ct.Close()
		pt.Close()
		ctx.Close()

		results = append(results, result)
	}

	// Print comparison table
	fmt.Println("\nBasic Parameters:")
	fmt.Printf("%-12s | %-10s | %-8s | %-16s | %-10s\n",
		"MultDepth", "RingDim", "Pages", "Buckets/Page", "CT Size")
	fmt.Println("-------------|------------|----------|------------------|------------")
	for _, r := range results {
		fmt.Printf("%-12d | %-10d | %-8d | %-16d | %8d B\n",
			r.MultDepth, r.RingDim, r.NumPages, r.BucketsPerPage, r.CiphertextBytes)
	}

	fmt.Println("\nOperation Timings:")
	fmt.Printf("%-12s | %-12s | %-12s | %-12s | %-12s | %-12s\n",
		"RingDim", "Encrypt", "Decrypt", "MultPlain", "Add", "Rotate")
	fmt.Println("-------------|--------------|--------------|--------------|--------------|-------------")
	for _, r := range results {
		fmt.Printf("%-12d | %10.3f ms | %10.3f ms | %10.3f ms | %10.3f ms | %10.3f ms\n",
			r.RingDim,
			r.EncryptionTime.Seconds()*1000,
			r.DecryptionTime.Seconds()*1000,
			r.MultPlainTime.Seconds()*1000,
			r.AddTime.Seconds()*1000,
			r.RotationTime.Seconds()*1000)
	}

	fmt.Println("\nBandwidth Estimates:")
	fmt.Printf("%-12s | %-18s | %-18s | %-12s\n",
		"RingDim", "24-CT Upload", "Paged Upload", "Savings")
	fmt.Println("-------------|--------------------|--------------------|-------------")
	for _, r := range results {
		savings := float64(r.EstimatedUpload-r.EstimatedPaged) / float64(r.EstimatedUpload) * 100
		fmt.Printf("%-12d | %15.2f MB | %15.2f MB | %10.1f %%\n",
			r.RingDim,
			float64(r.EstimatedUpload)/1024/1024,
			float64(r.EstimatedPaged)/1024/1024,
			savings)
	}

	fmt.Println("\nPerformance Comparison (relative to ringDim=8192):")
	fmt.Printf("%-12s | %-12s | %-12s | %-12s\n",
		"RingDim", "Encrypt", "Ops", "Upload")
	fmt.Println("-------------|--------------|--------------|-------------")
	baseline := results[0]
	for _, r := range results {
		encryptRatio := float64(r.EncryptionTime) / float64(baseline.EncryptionTime)
		opsRatio := float64(r.MultPlainTime) / float64(baseline.MultPlainTime)
		uploadRatio := float64(r.EstimatedPaged) / float64(baseline.EstimatedPaged)
		fmt.Printf("%-12d | %10.2f x | %10.2f x | %10.2f x\n",
			r.RingDim, encryptRatio, opsRatio, uploadRatio)
	}
}

// BenchmarkEndToEnd24CT benchmarks full PIR query with different ringDim values (24-CT approach)
func BenchmarkEndToEnd24CT(b *testing.B) {
	configs := []struct {
		multDepth uint32
		name      string
	}{
		{1, "RingDim8K"},
		{2, "RingDim16K"},
	}

	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			benchmarkEndToEnd24CTSingle(b, config.multDepth)
		})
	}
}

func benchmarkEndToEnd24CTSingle(b *testing.B, multDepth uint32) {
	// Create custom context
	ctx, err := NewFHEContextCustom(multDepth)
	require.NoError(b, err)
	defer ctx.Close()

	err = ctx.GenerateKeys()
	require.NoError(b, err)

	// Create routing table
	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, _ := pstoremem.NewPeerstore()
	rt, _ := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)

	// Enable FHE (convert custom context to regular context)
	fheCtx := &FHEContext{
		CC:      ctx.cc,
		KP:      ctx.kp,
		params:  ctx.params,
		ringDim: ctx.ringDim,
	}
	rt.EnableFHE(fheCtx)

	// Add peers
	peerCount := 100
	for i := 0; i < peerCount*2; i++ {
		p := test.RandPeerIDFatal(b)
		addrs := generateLargeMultiaddrs(i)
		ps.AddAddrs(p, addrs, time.Hour)
		rt.TryAddPeer(p, true, false)
	}

	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)
	targetCPL := CommonPrefixLen(targetID, localID)

	var totalTime time.Duration
	var queryTime time.Duration
	var pirTime time.Duration
	var decryptTime time.Duration

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()

		// Query creation
		qStart := time.Now()
		queryVec, _ := fheCtx.CreateQueryVector(targetCPL)
		queryTime += time.Since(qStart)

		// PIR computation
		pStart := time.Now()

		// Add addresses to peerstore
		rt.tabLock.RLock()
		for _, bucket := range rt.buckets {
			for _, pInfo := range bucket.peers() {
				addr, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000))
				ps.AddAddrs(pInfo.Id, []ma.Multiaddr{addr}, time.Hour)
			}
		}
		rt.tabLock.RUnlock()

		encResp, _ := rt.GetBucketPIR(queryVec, ps)
		pirTime += time.Since(pStart)

		// Decryption
		dStart := time.Now()
		_, _ = fheCtx.DecryptConnectablePeers(encResp)
		decryptTime += time.Since(dStart)

		totalTime += time.Since(start)

		// Cleanup
		encResp.Close()
		for _, ct := range queryVec {
			ct.Close()
		}
	}

	b.StopTimer()

	// Estimate upload size
	ctSize := 2 * ctx.ringDim * 8
	uploadSize := MaxCPL * ctSize

	b.ReportMetric(float64(queryTime.Milliseconds())/float64(b.N), "ms/query")
	b.ReportMetric(float64(pirTime.Milliseconds())/float64(b.N), "ms/pir")
	b.ReportMetric(float64(decryptTime.Milliseconds())/float64(b.N), "ms/decrypt")
	b.ReportMetric(float64(totalTime.Milliseconds())/float64(b.N), "ms/total")
	b.ReportMetric(float64(uploadSize)/1024/1024, "MB/upload")
	b.ReportMetric(float64(ctx.ringDim), "ring_dim")
}

// BenchmarkEndToEndPaged benchmarks full PIR query with different ringDim values (Paged approach)
func BenchmarkEndToEndPaged(b *testing.B) {
	configs := []struct {
		multDepth uint32
		name      string
	}{
		{1, "RingDim8K"},
		{2, "RingDim16K"},
	}

	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			benchmarkEndToEndPagedSingle(b, config.multDepth)
		})
	}
}

func benchmarkEndToEndPagedSingle(b *testing.B, multDepth uint32) {
	// Create custom context
	ctx, err := NewFHEContextCustom(multDepth)
	require.NoError(b, err)
	defer ctx.Close()

	err = ctx.GenerateKeys()
	require.NoError(b, err)

	// Create routing table
	local := test.RandPeerIDFatal(b)
	localID := ConvertPeerID(local)
	ps, _ := pstoremem.NewPeerstore()
	rt, _ := NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil, nil)

	// Enable FHE
	fheCtx := &FHEContext{
		CC:      ctx.cc,
		KP:      ctx.kp,
		params:  ctx.params,
		ringDim: ctx.ringDim,
	}
	rt.EnableFHE(fheCtx)

	// Add peers
	peerCount := 100
	for i := 0; i < peerCount*2; i++ {
		p := test.RandPeerIDFatal(b)
		addrs := generateLargeMultiaddrs(i)
		ps.AddAddrs(p, addrs, time.Hour)
		rt.TryAddPeer(p, true, false)
	}

	target := test.RandPeerIDFatal(b)
	targetID := ConvertPeerID(target)
	targetCPL := CommonPrefixLen(targetID, localID)

	// Calculate pages
	bucketsPerPage := ctx.ringDim / BucketStride
	numPages := MaxCPL / bucketsPerPage
	if MaxCPL%bucketsPerPage != 0 {
		numPages++
	}

	var totalTime time.Duration
	var queryTime time.Duration
	var pirTime time.Duration
	var decryptTime time.Duration

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()

		// Query creation
		qStart := time.Now()
		queryVec, _ := fheCtx.CreateQueryVectorPaged(targetCPL)
		queryTime += time.Since(qStart)

		// PIR computation
		pStart := time.Now()

		// Add addresses
		rt.tabLock.RLock()
		for _, bucket := range rt.buckets {
			for _, pInfo := range bucket.peers() {
				addr, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000))
				ps.AddAddrs(pInfo.Id, []ma.Multiaddr{addr}, time.Hour)
			}
		}
		rt.tabLock.RUnlock()

		encResp, _ := rt.GetBucketPIRPaged(queryVec, ps)
		pirTime += time.Since(pStart)

		// Decryption
		dStart := time.Now()
		_, _ = fheCtx.DecryptConnectablePeersPaged(encResp, targetCPL)
		decryptTime += time.Since(dStart)

		totalTime += time.Since(start)

		// Cleanup
		encResp.Close()
		for _, ct := range queryVec {
			ct.Close()
		}
	}

	b.StopTimer()

	// Estimate upload size
	ctSize := 2 * ctx.ringDim * 8
	uploadSize := numPages * ctSize

	b.ReportMetric(float64(queryTime.Milliseconds())/float64(b.N), "ms/query")
	b.ReportMetric(float64(pirTime.Milliseconds())/float64(b.N), "ms/pir")
	b.ReportMetric(float64(decryptTime.Milliseconds())/float64(b.N), "ms/decrypt")
	b.ReportMetric(float64(totalTime.Milliseconds())/float64(b.N), "ms/total")
	b.ReportMetric(float64(uploadSize)/1024/1024, "MB/upload")
	b.ReportMetric(float64(ctx.ringDim), "ring_dim")
	b.ReportMetric(float64(numPages), "num_pages")
	b.ReportMetric(float64(bucketsPerPage), "buckets/page")
}
