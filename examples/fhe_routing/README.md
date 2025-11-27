# FHE-Based Private Routing Table Lookup Example

This example demonstrates privacy-preserving peer lookups in a Kademlia routing table using Fully Homomorphic Encryption (FHE) with the **Greedy Adaptive PIR** mechanism.

## Overview

In traditional DHT routing table lookups, the querying node reveals the target peer ID to every node it contacts. This FHE-based approach using Greedy Adaptive PIR provides:

- **Client Privacy**: The target peer ID remains encrypted and unknown to the server
- **Efficient Queries**: Single packed ciphertext query (not 24 separate ciphertexts)
- **Adaptive Response**: Response size adapts to bucket capacity (1+ ciphertexts)
- **Strong Security**: Destructive Summation ensures only 1 bucket is retrievable
- **Good Performance**: Optimized for real-world routing table sizes

## Privacy Model

**What the server learns:**
- Which bucket (approximate CPL region) the target is in
- This is equivalent to learning `CommonPrefixLen(target, local_id)`

**What the server does NOT learn:**
- The actual target peer ID
- Which specific peer within the bucket the client wants

**Why this is useful:**
- Significantly better than revealing the exact target ID
- Matches Kademlia's bucket-based routing paradigm
- Allows client-side filtering for exact K-nearest peers

## Prerequisites

### 1. Install OpenFHE C++ Library

```bash
# Clone OpenFHE
git clone https://github.com/openfheorg/openfhe-development.git
cd openfhe-development

# Build and install
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

### 2. Set Library Path

```bash
# Add to ~/.bashrc or ~/.zshrc
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH  # Linux
# or
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH  # macOS
```

## Building

```bash
# Build with FHE support
go build -tags openfhe -o fhe_routing

# Or without FHE (stub implementation)
go build -o fhe_routing
```

## Running

```bash
./fhe_routing
```

## Expected Output

```
=== FHE-Based Private Routing Table Lookup (Greedy Adaptive PIR) ===

1. Setting up FHE context...
   ✓ FHE context created with STD128 security
   ✓ Rotation keys generated for Greedy Adaptive PIR

2. Creating server routing table...
   ✓ Routing table created for peer QmXXXX...
   ✓ FHE enabled with Greedy Adaptive PIR

3. Populating routing table with peers...
   ✓ Added 50 peers to routing table

4. Client selects target peer to search for...
   Target peer: QmYYYY...
   Target CPL:  5

5. Traditional lookup (server learns target)...
   Found 10 peers in 125µs

6. FHE-based private lookup (Greedy Adaptive PIR)...
   a) Client creates encrypted query vector...
      ✓ Query encryption took 35ms
      ✓ Single packed ciphertext (not 24 separate ciphertexts!)
   b) Server processes encrypted query...
      ✓ Server computed PIR response in 65ms
      ✓ Returned 1 ciphertext(s) (adaptive to bucket size)
      ✓ Server never learned the target ID!
   c) Client decrypts response...
      ✓ Decryption took 15ms
      ✓ Retrieved 20 peers from bucket
   d) Client filters locally to find K-nearest...
      ✓ Found 10 nearest peers

7. Comparing results...
   Traditional time: 125µs
   FHE time:         115ms (920x slower)
   
   Breakdown:
     - Query creation:  35ms
     - Server PIR:      65ms
     - Client decrypt:  15ms
   
   Privacy gain: Target ID completely hidden from server
   Security:     Destructive Summation ensures only 1 bucket retrievable

8. Verifying correctness...
   ✓ 10/10 peers match (100.0% accuracy)

=== Example Complete ===

Key Takeaways:
  • Greedy Adaptive PIR uses single packed ciphertext (not 24)
  • Adapts response size to bucket capacity (1+ ciphertexts)
  • Server never learns the target peer ID
  • Destructive Summation ensures only 1 bucket is retrievable
  • Client can filter results locally for exact K-nearest
  • Performance is excellent for privacy-sensitive applications
```

## Architecture

### Greedy Adaptive PIR Method

The example uses the **Greedy Adaptive PIR** mechanism, which provides:

1. **Single Packed Query**: Query is 1 ciphertext with a one-hot vector in SIMD slots
2. **Destructive Summation**: Server sums all buckets weighted by query bits
3. **Adaptive Response**: Returns 1+ ciphertexts based on maximum bucket size
4. **Dense Packing**: Efficiently packs peer data (2 bytes per slot)

### Client Side
```
1. cpl = CommonPrefixLen(target_id, local_id)
2. query = CreateOneHotVector(cpl)        // [0,0,1,0,0...] at position cpl
3. enc_query = FHE.Encrypt(query)         // Single packed ciphertext
4. Send enc_query to server
5. Receive encrypted response (1+ ciphertexts)
6. Decrypt and deserialize bucket peers
7. Filter locally for K-nearest
```

### Server Side
```
1. Receive enc_query (single packed ciphertext)
2. For each bucket i:
   a. Extract bit[i] from query and replicate across slots
   b. Multiply selector * bucket_data
   c. Add to accumulator
3. Result: Only the selected bucket survives, others are zeroed
4. Return encrypted accumulator(s)
5. Server never learns which bit was 1 (which bucket was selected)
```

### Why "Greedy Adaptive"?

- **Greedy**: Uses destructive summation - only 1 bucket can be retrieved
- **Adaptive**: Response size adapts to maximum bucket capacity
  - Small buckets → 1 ciphertext (~32KB capacity)
  - Large buckets → 2+ ciphertexts (scales as needed)

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Create query vector | 20-40ms | Client-side, single packed ciphertext |
| Server PIR computation | 50-100ms | Server-side, homomorphic operations |
| Decrypt response | 10-20ms per CT | Client-side, 1+ ciphertexts |
| Local K-nearest filtering | <1ms | Client-side, plaintext sorting |
| **Total FHE overhead** | **~80-160ms** | vs ~100µs for plaintext |

### Performance Advantages over Basic PIR

- **Single Query CT**: 1 ciphertext vs 24 (24x reduction in upload)
- **Adaptive Response**: Only returns what's needed (1-2 CTs typically)
- **Efficient Packing**: Dense serialization (2 bytes/slot) vs sparse (8 bytes/slot)
- **Better Security**: Destructive summation prevents multi-bucket retrieval

## Use Cases

1. **Privacy-Sensitive Content Discovery**: Finding content without revealing what you're looking for
2. **Anonymous Peer Discovery**: Joining swarms without exposing interests
3. **Censorship Resistance**: Routing queries that can't be filtered by topic
4. **Compliance**: Meeting privacy regulations (GDPR, etc.) for DHT lookups

## API Usage

```go
// 1. Server setup
fheCtx, _ := kbucket.NewFHEContext()
fheCtx.GenerateKeysWithRotation()  // Required for Greedy Adaptive PIR

ps, _ := pstoremem.NewPeerstore()
rt, _ := kbucket.NewRoutingTable(20, localID, time.Hour, ps, time.Hour, nil)
rt.EnableFHE(fheCtx)

// 2. Client creates query
targetID := kbucket.ConvertPeerID(targetPeer)
targetCPL := kbucket.CommonPrefixLen(localID, targetID)
queryCt, _ := fheCtx.CreateQueryVectorGreedy(targetCPL)

// 3. Server processes encrypted query (returns 1+ ciphertexts)
responseCts, _ := rt.GetBucketPIRGreedyAdaptive(queryCt, ps)

// 4. Client decrypts response
bucketPeers, _ := fheCtx.DecryptGreedyAdaptiveResponse(responseCts)

// 5. Client filters locally for K-nearest
nearest := findKNearest(bucketPeers, targetID, 10)
```

### Key API Differences from Basic PIR

- `GenerateKeysWithRotation()` instead of `GenerateKeys()` (rotation keys required)
- `CreateQueryVectorGreedy(cpl)` returns single `*Ciphertext` (not array)
- `GetBucketPIRGreedyAdaptive()` returns `[]*Ciphertext` (adaptive size)
- `DecryptGreedyAdaptiveResponse()` handles multi-ring responses

## Limitations

- **Performance**: 100-1000x slower than plaintext (acceptable for many use cases)
- **Bucket granularity**: Server learns approximate region (CPL)
- **Dependencies**: Requires OpenFHE C++ library installation
- **Maturity**: openfhe-go is work in progress

## References

- [OpenFHE](https://github.com/openfheorg/openfhe-development): C++ FHE library
- [openfhe-go](https://github.com/dozyio/openfhe-go): Go bindings
- [Kademlia DHT](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf): Original paper
- [libp2p](https://libp2p.io/): Modular network stack
