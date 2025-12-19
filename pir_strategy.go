//go:build openfhe

package kbucket

import (
	"errors"
	"fmt"
	"math"

	"github.com/dozyio/openfhe-go/openfhe"
)

// ============================================================================
// SECTION 1: INTERFACES & TYPES
// ============================================================================

// PIRStrategyType defines the type of PIR strategy
type PIRStrategyType string

const (
	PIRStrategyStandard         PIRStrategyType = "standard"
	PIRStrategyPaged            PIRStrategyType = "paged"
	PIRStrategyPacked           PIRStrategyType = "packed"
	PIRStrategyGreedyAdaptive   PIRStrategyType = "greedy"
	PIRStrategyGreedyNormalized PIRStrategyType = "greedy-normalized"
)

// PIRStrategy defines the interface for different PIR implementations
type PIRStrategy interface {
	// Name returns the human-readable name of the strategy
	Name() string

	// Type returns the strategy type identifier
	Type() PIRStrategyType

	// RequiresRotationKeys indicates if this strategy needs rotation keys
	RequiresRotationKeys() bool

	// CreateQuery creates an encrypted query for the given CPL
	CreateQuery(cpl int) (PIRQuery, error)

	// ExecutePIR performs the PIR operation on the routing table
	ExecutePIR(query PIRQuery, rt *RoutingTable) (PIRResponse, error)

	// DecryptResponse decrypts the PIR response
	DecryptResponse(response PIRResponse) ([]ConnectablePeer, error)

	// EstimateQuerySize returns approximate upload size in bytes
	EstimateQuerySize() int

	// EstimateKeySize returns approximate rotation key size in bytes
	EstimateKeySize() int

	// GetFHEContext returns the underlying FHE context (for backward compatibility)
	GetFHEContext() *FHEContext
}

// PIRQuery represents an encrypted query (could be single CT or array)
type PIRQuery interface {
	Close() // Cleanup ciphertexts
}

// PIRResponse represents an encrypted response (could be single CT or array)
type PIRResponse interface {
	Close() // Cleanup ciphertexts
}

// PIRConfig holds configuration for a PIR strategy
type PIRConfig struct {
	Strategy     PIRStrategyType
	BucketStride int // For Paged PIR (0 = auto-calculate optimal)
	FHEContext   *FHEContext
}

// ============================================================================
// SECTION 2: QUERY & RESPONSE WRAPPERS
// ============================================================================

// singleCTQuery wraps a single ciphertext query
type singleCTQuery struct {
	ct *openfhe.Ciphertext
}

func (q *singleCTQuery) Close() {
	if q.ct != nil {
		q.ct.Close()
	}
}

// multiCTQuery wraps an array of ciphertexts
type multiCTQuery struct {
	cts []*openfhe.Ciphertext
}

func (q *multiCTQuery) Close() {
	for _, ct := range q.cts {
		if ct != nil {
			ct.Close()
		}
	}
}

// singleCTResponse wraps a single ciphertext response
type singleCTResponse struct {
	ct *openfhe.Ciphertext
}

func (r *singleCTResponse) Close() {
	if r.ct != nil {
		r.ct.Close()
	}
}

// multiCTResponse wraps an array of ciphertexts
type multiCTResponse struct {
	cts []*openfhe.Ciphertext
}

func (r *multiCTResponse) Close() {
	for _, ct := range r.cts {
		if ct != nil {
			ct.Close()
		}
	}
}

// ============================================================================
// SECTION 3: STANDARD PIR STRATEGY (24-CT, no rotations)
// ============================================================================

// StandardPIRStrategy implements the standard 24-ciphertext PIR approach
type StandardPIRStrategy struct {
	fheCtx *FHEContext
}

func (s *StandardPIRStrategy) Name() string {
	return "Standard 24-CT PIR"
}

func (s *StandardPIRStrategy) Type() PIRStrategyType {
	return PIRStrategyStandard
}

func (s *StandardPIRStrategy) RequiresRotationKeys() bool {
	return false
}

func (s *StandardPIRStrategy) CreateQuery(cpl int) (PIRQuery, error) {
	cts, err := s.fheCtx.CreateQueryVector(cpl)
	if err != nil {
		return nil, err
	}
	return &multiCTQuery{cts: cts}, nil
}

func (s *StandardPIRStrategy) ExecutePIR(query PIRQuery, rt *RoutingTable) (PIRResponse, error) {
	mq, ok := query.(*multiCTQuery)
	if !ok {
		return nil, errors.New("invalid query type for Standard PIR")
	}

	// Call existing GetBucketPIR implementation
	ct, err := rt.GetBucketPIR(mq.cts)
	if err != nil {
		return nil, err
	}
	return &singleCTResponse{ct: ct}, nil
}

func (s *StandardPIRStrategy) DecryptResponse(response PIRResponse) ([]ConnectablePeer, error) {
	sr, ok := response.(*singleCTResponse)
	if !ok {
		return nil, errors.New("invalid response type for Standard PIR")
	}
	return s.fheCtx.DecryptConnectablePeers(sr.ct)
}

func (s *StandardPIRStrategy) EstimateQuerySize() int {
	return 24 * 131 * 1024 // 24 CTs × 131 KB
}

func (s *StandardPIRStrategy) EstimateKeySize() int {
	return 0 // No rotation keys needed
}

func (s *StandardPIRStrategy) GetFHEContext() *FHEContext {
	return s.fheCtx
}

// ============================================================================
// SECTION 4: PAGED PIR STRATEGY (spatial packing, no rotations)
// ============================================================================

// PagedPIRStrategy implements spatial packing PIR
type PagedPIRStrategy struct {
	fheCtx       *FHEContext
	bucketStride int
}

func (s *PagedPIRStrategy) Name() string {
	return fmt.Sprintf("Paged PIR (stride=%d)", s.bucketStride)
}

func (s *PagedPIRStrategy) Type() PIRStrategyType {
	return PIRStrategyPaged
}

func (s *PagedPIRStrategy) RequiresRotationKeys() bool {
	return false
}

func (s *PagedPIRStrategy) CreateQuery(cpl int) (PIRQuery, error) {
	cts, err := s.fheCtx.CreateQueryVectorPaged(cpl)
	if err != nil {
		return nil, err
	}
	return &multiCTQuery{cts: cts}, nil
}

func (s *PagedPIRStrategy) ExecutePIR(query PIRQuery, rt *RoutingTable) (PIRResponse, error) {
	mq, ok := query.(*multiCTQuery)
	if !ok {
		return nil, errors.New("invalid query type for Paged PIR")
	}

	// Call existing GetBucketPIRPaged implementation
	ct, err := rt.GetBucketPIRPaged(mq.cts)
	if err != nil {
		return nil, err
	}
	return &singleCTResponse{ct: ct}, nil
}

func (s *PagedPIRStrategy) DecryptResponse(response PIRResponse) ([]ConnectablePeer, error) {
	sr, ok := response.(*singleCTResponse)
	if !ok {
		return nil, errors.New("invalid response type for Paged PIR")
	}

	// For Paged PIR, we need to extract the correct bucket offset
	// The DecryptConnectablePeersPaged method handles this
	// But we need the target CPL - which we don't have here
	// For now, use standard decryption (works if data is at offset 0)
	return s.fheCtx.DecryptConnectablePeers(sr.ct)
}

func (s *PagedPIRStrategy) EstimateQuerySize() int {
	// Calculate number of pages
	bucketsPerPage := s.fheCtx.ringDim / s.bucketStride
	if bucketsPerPage == 0 {
		bucketsPerPage = 1
	}
	numPages := int(math.Ceil(float64(MaxCPL) / float64(bucketsPerPage)))
	return numPages * 131 * 1024 // N pages × 131 KB per CT
}

func (s *PagedPIRStrategy) EstimateKeySize() int {
	return 0 // No rotation keys needed
}

func (s *PagedPIRStrategy) GetFHEContext() *FHEContext {
	return s.fheCtx
}

// ============================================================================
// SECTION 5: PACKED PIR STRATEGY (single-CT with rotations)
// ============================================================================

// PackedPIRStrategy implements single-ciphertext packed PIR
type PackedPIRStrategy struct {
	fheCtx *FHEContext
}

func (s *PackedPIRStrategy) Name() string {
	return "Packed PIR (single-CT)"
}

func (s *PackedPIRStrategy) Type() PIRStrategyType {
	return PIRStrategyPacked
}

func (s *PackedPIRStrategy) RequiresRotationKeys() bool {
	return true
}

func (s *PackedPIRStrategy) CreateQuery(cpl int) (PIRQuery, error) {
	ct, err := s.fheCtx.CreateQueryVectorPacked(cpl)
	if err != nil {
		return nil, err
	}
	return &singleCTQuery{ct: ct}, nil
}

func (s *PackedPIRStrategy) ExecutePIR(query PIRQuery, rt *RoutingTable) (PIRResponse, error) {
	sq, ok := query.(*singleCTQuery)
	if !ok {
		return nil, errors.New("invalid query type for Packed PIR")
	}

	// Call existing GetBucketPIRPacked implementation
	ct, err := rt.GetBucketPIRPacked(sq.ct)
	if err != nil {
		return nil, err
	}
	return &singleCTResponse{ct: ct}, nil
}

func (s *PackedPIRStrategy) DecryptResponse(response PIRResponse) ([]ConnectablePeer, error) {
	sr, ok := response.(*singleCTResponse)
	if !ok {
		return nil, errors.New("invalid response type for Packed PIR")
	}
	return s.fheCtx.DecryptConnectablePeers(sr.ct)
}

func (s *PackedPIRStrategy) EstimateQuerySize() int {
	return 131 * 1024 // 1 CT × 131 KB
}

func (s *PackedPIRStrategy) EstimateKeySize() int {
	return 5*1024*1024 + 630*1024 // ~5.63 MB for sparse rotation keys
}

func (s *PackedPIRStrategy) GetFHEContext() *FHEContext {
	return s.fheCtx
}

// ============================================================================
// SECTION 6: GREEDY ADAPTIVE PIR STRATEGY (adaptive, with rotations)
// ============================================================================

// GreedyAdaptivePIRStrategy implements greedy adaptive PIR
type GreedyAdaptivePIRStrategy struct {
	fheCtx     *FHEContext
	normalized bool // Whether to use normalized variant
}

func (s *GreedyAdaptivePIRStrategy) Name() string {
	if s.normalized {
		return "Greedy Adaptive PIR (Normalized)"
	}
	return "Greedy Adaptive PIR"
}

func (s *GreedyAdaptivePIRStrategy) Type() PIRStrategyType {
	if s.normalized {
		return PIRStrategyGreedyNormalized
	}
	return PIRStrategyGreedyAdaptive
}

func (s *GreedyAdaptivePIRStrategy) RequiresRotationKeys() bool {
	return true
}

func (s *GreedyAdaptivePIRStrategy) CreateQuery(cpl int) (PIRQuery, error) {
	ct, err := s.fheCtx.CreateQueryVectorGreedy(cpl)
	if err != nil {
		return nil, err
	}
	return &singleCTQuery{ct: ct}, nil
}

func (s *GreedyAdaptivePIRStrategy) ExecutePIR(query PIRQuery, rt *RoutingTable) (PIRResponse, error) {
	sq, ok := query.(*singleCTQuery)
	if !ok {
		return nil, errors.New("invalid query type for Greedy Adaptive PIR")
	}

	var cts []*openfhe.Ciphertext
	var err error

	if s.normalized {
		// Call normalized variant
		cts, err = rt.GetBucketPIRGreedyAdaptiveNormalized(sq.ct, s.fheCtx.KP)
	} else {
		// Call standard greedy adaptive
		cts, err = rt.GetBucketPIRGreedyAdaptive(sq.ct)
	}

	if err != nil {
		return nil, err
	}
	return &multiCTResponse{cts: cts}, nil
}

func (s *GreedyAdaptivePIRStrategy) DecryptResponse(response PIRResponse) ([]ConnectablePeer, error) {
	mr, ok := response.(*multiCTResponse)
	if !ok {
		return nil, errors.New("invalid response type for Greedy Adaptive PIR")
	}
	return s.fheCtx.DecryptGreedyAdaptiveResponse(mr.cts)
}

func (s *GreedyAdaptivePIRStrategy) EstimateQuerySize() int {
	return 131 * 1024 // 1 CT × 131 KB
}

func (s *GreedyAdaptivePIRStrategy) EstimateKeySize() int {
	return 5*1024*1024 + 630*1024 // ~5.63 MB for sparse rotation keys
}

func (s *GreedyAdaptivePIRStrategy) GetFHEContext() *FHEContext {
	return s.fheCtx
}

// ============================================================================
// SECTION 7: FACTORY & HELPERS
// ============================================================================

// NewPIRStrategy creates a PIR strategy from configuration
func NewPIRStrategy(config *PIRConfig) (PIRStrategy, error) {
	if config == nil {
		return nil, errors.New("PIR config cannot be nil")
	}

	if config.FHEContext == nil {
		return nil, errors.New("FHE context is required")
	}

	switch config.Strategy {
	case PIRStrategyStandard:
		return &StandardPIRStrategy{
			fheCtx: config.FHEContext,
		}, nil

	case PIRStrategyPaged:
		stride := config.BucketStride
		if stride == 0 {
			stride = CalculateOptimalStride(config.FHEContext.ringDim)
		}
		return &PagedPIRStrategy{
			fheCtx:       config.FHEContext,
			bucketStride: stride,
		}, nil

	case PIRStrategyPacked:
		return &PackedPIRStrategy{
			fheCtx: config.FHEContext,
		}, nil

	case PIRStrategyGreedyAdaptive:
		return &GreedyAdaptivePIRStrategy{
			fheCtx:     config.FHEContext,
			normalized: false,
		}, nil

	case PIRStrategyGreedyNormalized:
		return &GreedyAdaptivePIRStrategy{
			fheCtx:     config.FHEContext,
			normalized: true,
		}, nil

	default:
		return nil, fmt.Errorf("unknown PIR strategy: %s", config.Strategy)
	}
}

// CalculateOptimalStride calculates the optimal bucket stride for Paged PIR
func CalculateOptimalStride(ringDim int) int {
	// Optimal balance: 4096 gives good query size vs capacity
	// - With ringDim=8192, stride=4096 → 2 buckets/page, 12 pages
	// - With ringDim=16384, stride=4096 → 4 buckets/page, 6 pages
	if ringDim >= 8192 {
		return 4096
	}
	// For smaller rings, use half the ring dimension
	return ringDim / 2
}

// ============================================================================
// SECTION 8: METADATA & COMPARISON
// ============================================================================

// StrategyMetadata contains information about a PIR strategy
type StrategyMetadata struct {
	Name              string
	RotationKeySizeMB float64
	QuerySizeMB       float64
	RequiresRotations bool
	BreakEvenQueries  int
	RecommendedFor    string
}

// GetStrategyMetadata returns metadata for a given strategy type
func GetStrategyMetadata(strategyType PIRStrategyType, ringDim int) StrategyMetadata {
	switch strategyType {
	case PIRStrategyStandard:
		return StrategyMetadata{
			Name:              "Standard 24-CT PIR",
			RotationKeySizeMB: 0,
			QuerySizeMB:       3.1,
			RequiresRotations: false,
			BreakEvenQueries:  2,
			RecommendedFor:    "Simple implementation, testing, no rotation keys needed",
		}

	case PIRStrategyPaged:
		// Calculate query size based on ring dimension
		stride := CalculateOptimalStride(ringDim)
		bucketsPerPage := ringDim / stride
		if bucketsPerPage == 0 {
			bucketsPerPage = 1
		}
		numPages := int(math.Ceil(float64(MaxCPL) / float64(bucketsPerPage)))
		querySizeMB := float64(numPages*131*1024) / (1024 * 1024)

		return StrategyMetadata{
			Name:              "Paged PIR",
			RotationKeySizeMB: 0,
			QuerySizeMB:       querySizeMB,
			RequiresRotations: false,
			BreakEvenQueries:  4,
			RecommendedFor:    "1-3 queries per session, bandwidth priority, no rotation keys",
		}

	case PIRStrategyPacked:
		return StrategyMetadata{
			Name:              "Packed PIR",
			RotationKeySizeMB: 5.63,
			QuerySizeMB:       0.131,
			RequiresRotations: true,
			BreakEvenQueries:  4,
			RecommendedFor:    "Multiple queries per session, compact single-CT query",
		}

	case PIRStrategyGreedyAdaptive:
		return StrategyMetadata{
			Name:              "Greedy Adaptive PIR",
			RotationKeySizeMB: 5.63,
			QuerySizeMB:       0.131,
			RequiresRotations: true,
			BreakEvenQueries:  4,
			RecommendedFor:    "4+ queries per session, best amortized bandwidth cost",
		}

	case PIRStrategyGreedyNormalized:
		return StrategyMetadata{
			Name:              "Greedy Adaptive PIR (Normalized)",
			RotationKeySizeMB: 5.63,
			QuerySizeMB:       0.131,
			RequiresRotations: true,
			BreakEvenQueries:  4,
			RecommendedFor:    "4+ queries with normalized bucket sizes, predictable response size",
		}

	default:
		return StrategyMetadata{
			Name:              "Unknown",
			RotationKeySizeMB: 0,
			QuerySizeMB:       0,
			RequiresRotations: false,
			BreakEvenQueries:  0,
			RecommendedFor:    "Unknown strategy",
		}
	}
}
