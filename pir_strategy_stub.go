//go:build !openfhe

package kbucket

import (
	"errors"
)

// PIRStrategyType stub
type PIRStrategyType string

const (
	PIRStrategyStandard         PIRStrategyType = "standard"
	PIRStrategyPaged            PIRStrategyType = "paged"
	PIRStrategyPacked           PIRStrategyType = "packed"
	PIRStrategyGreedyAdaptive   PIRStrategyType = "greedy"
	PIRStrategyGreedyNormalized PIRStrategyType = "greedy-normalized"
)

// PIRQuery stub
type PIRQuery interface {
	Close()
}

// PIRResponse stub
type PIRResponse interface {
	Close()
}

// ConnectablePeer stub
type ConnectablePeer struct{}

// PIRStrategy stub interface
type PIRStrategy interface {
	Name() string
	Type() PIRStrategyType
	RequiresRotationKeys() bool
	CreateQuery(cpl int) (PIRQuery, error)
	ExecutePIR(query PIRQuery, rt *RoutingTable) (PIRResponse, error)
	DecryptResponse(response PIRResponse) ([]ConnectablePeer, error)
	EstimateQuerySize() int
	EstimateKeySize() int
	GetFHEContext() *FHEContext
}

// PIRConfig stub
type PIRConfig struct {
	Strategy     PIRStrategyType
	BucketStride int
	FHEContext   *FHEContext
}

// StrategyMetadata stub
type StrategyMetadata struct {
	Name              string
	RotationKeySizeMB float64
	QuerySizeMB       float64
	RequiresRotations bool
	BreakEvenQueries  int
	RecommendedFor    string
}

// pirStrategyStub is a stub implementation
type pirStrategyStub struct{}

func (s *pirStrategyStub) Name() string {
	return "PIR Not Available (rebuild with -tags openfhe)"
}

func (s *pirStrategyStub) Type() PIRStrategyType {
	return ""
}

func (s *pirStrategyStub) RequiresRotationKeys() bool {
	return false
}

func (s *pirStrategyStub) CreateQuery(cpl int) (PIRQuery, error) {
	return nil, errors.New("PIR support not compiled in")
}

func (s *pirStrategyStub) ExecutePIR(query PIRQuery, rt *RoutingTable) (PIRResponse, error) {
	return nil, errors.New("PIR support not compiled in")
}

func (s *pirStrategyStub) DecryptResponse(response PIRResponse) ([]ConnectablePeer, error) {
	return nil, errors.New("PIR support not compiled in")
}

func (s *pirStrategyStub) EstimateQuerySize() int {
	return 0
}

func (s *pirStrategyStub) EstimateKeySize() int {
	return 0
}

func (s *pirStrategyStub) GetFHEContext() *FHEContext {
	return nil
}

// NewPIRStrategy stub
func NewPIRStrategy(config *PIRConfig) (PIRStrategy, error) {
	return nil, errors.New("PIR support not compiled in; rebuild with -tags openfhe")
}

// GetStrategyMetadata stub
func GetStrategyMetadata(strategyType PIRStrategyType, ringDim int) StrategyMetadata {
	return StrategyMetadata{
		Name:              "PIR Not Available",
		RotationKeySizeMB: 0,
		QuerySizeMB:       0,
		RequiresRotations: false,
		BreakEvenQueries:  0,
		RecommendedFor:    "Rebuild with -tags openfhe to enable PIR",
	}
}

// CalculateOptimalStride stub
func CalculateOptimalStride(ringDim int) int {
	return 4096
}
