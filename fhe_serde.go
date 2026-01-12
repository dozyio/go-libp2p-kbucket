//go:build openfhe

package kbucket

import (
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// ConnectablePeer is the data structure we actually send to the client.
// It contains only the information the client needs to connect.
type ConnectablePeer struct {
	ID    peer.ID        `json:"id"`
	Addrs []ma.Multiaddr `json:"addrs"`
}

// SerializeConnectablePeers converts a list of connectable peers into int64s
// using JSON as the intermediate format.
func SerializeConnectablePeers(peers []ConnectablePeer) ([]int64, error) {
	// 1. Serialize to JSON
	data, err := json.Marshal(peers)
	if err != nil {
		return nil, fmt.Errorf("failed to encode connectable peers to json: %w", err)
	}

	// 2. Pack bytes into int64 vector
	result := make([]int64, len(data))
	for i, b := range data {
		result[i] = int64(b)
	}

	return result, nil
}

// DeserializeConnectablePeers converts decrypted int64s back into connectable peers
// using JSON as the intermediate format.
func DeserializeConnectablePeers(data []int64) ([]ConnectablePeer, error) {
	// 1. Unpack int64s back to bytes
	byteData := make([]byte, 0, len(data))
	foundData := false
	for _, v := range data {
		if v < 0 || v > 255 {
			// This slot is noise, skip it
			continue
		}

		// Skip leading zeros (from packed PIR where data might start at non-zero slot)
		if !foundData && v == 0 {
			continue
		}

		// Once we find non-zero data, start collecting
		if v != 0 {
			foundData = true
		}

		// Stop at NULL byte AFTER we've found data (end of JSON)
		if foundData && v == 0 {
			break
		}

		byteData = append(byteData, byte(v))
	}

	// Handle the case where the decrypted result is just empty padding
	if len(byteData) == 0 {
		// This can happen if the selected bucket was empty.
		// Return an empty, non-nil slice.
		return []ConnectablePeer{}, nil
	}

	// 2. Deserialize from JSON
	var peers []ConnectablePeer
	if err := json.Unmarshal(byteData, &peers); err != nil {
		// Include the problematic string for debugging
		return nil, fmt.Errorf("failed to decode connectable peers from json: %w (data: %q)", err, string(byteData))
	}

	return peers, nil
}

// SerializeConnectablePeersDense converts peers to int64s using dense 2-byte packing.
// Each int64 holds 2 bytes of data, maximizing capacity (~32KB per ring vs ~16KB).
func SerializeConnectablePeersDense(peers []ConnectablePeer) ([]int64, error) {
	// 1. Serialize to JSON
	data, err := json.Marshal(peers)
	if err != nil {
		return nil, fmt.Errorf("failed to encode connectable peers to json: %w", err)
	}

	// 2. Pack 2 bytes per int64
	// Each int64 = (byte[i] << 8) | byte[i+1]
	numSlots := (len(data) + 1) / 2 // Round up
	result := make([]int64, numSlots)

	for i := 0; i < len(data); i += 2 {
		high := int64(data[i])
		low := int64(0)
		if i+1 < len(data) {
			low = int64(data[i+1])
		}
		result[i/2] = (high << 8) | low
	}

	return result, nil
}

// DeserializeConnectablePeersDense converts densely-packed int64s back to peers.
// Each int64 contains 2 bytes: high byte and low byte.
func DeserializeConnectablePeersDense(data []int64) ([]ConnectablePeer, error) {
	// 1. Unpack int64s to bytes (2 bytes per slot)
	byteData := make([]byte, 0, len(data)*2)
	foundData := false

	for _, v := range data {
		// Extract high and low bytes
		high := byte((v >> 8) & 0xFF)
		low := byte(v & 0xFF)

		// Skip leading zeros
		if !foundData && high == 0 && low == 0 {
			continue
		}

		// Once we find non-zero data, start collecting
		if !foundData && (high != 0 || low != 0) {
			foundData = true
		}

		// Add high byte if it's not zero or we're still collecting data
		if high != 0 {
			byteData = append(byteData, high)
		}

		// Add low byte if it's not zero or we're still collecting data
		if low != 0 {
			byteData = append(byteData, low)
		}
	}

	// Handle empty data case
	if len(byteData) == 0 {
		return []ConnectablePeer{}, nil
	}

	// Trim any trailing null bytes from the JSON data
	// This handles cases where padding was added
	for len(byteData) > 0 && byteData[len(byteData)-1] == 0 {
		byteData = byteData[:len(byteData)-1]
	}

	// 2. Deserialize from JSON
	var peers []ConnectablePeer
	if err := json.Unmarshal(byteData, &peers); err != nil {
		return nil, fmt.Errorf("failed to decode connectable peers from json: %w (data: %q)", err, string(byteData))
	}

	return peers, nil
}
