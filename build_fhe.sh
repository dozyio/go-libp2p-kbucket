#!/bin/bash
#
# Build and test go-libp2p-kbucket with FHE support using local OpenFHE installation
#
# This script uses the OpenFHE installation at /Users/z/code/github.com/dozyio/openfhe-go/openfhe-install
# which is built as part of the openfhe-go repository.

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

OPENFHE_INSTALL_DIR="/Users/z/code/github.com/dozyio/openfhe-go/openfhe-install"

# Check if OpenFHE is installed
if [ ! -f "${OPENFHE_INSTALL_DIR}/.installed" ]; then
  echo "ERROR: OpenFHE not found at ${OPENFHE_INSTALL_DIR}"
  echo "Please build openfhe-go first:"
  echo "  cd /Users/z/code/github.com/dozyio/openfhe-go"
  echo "  make build"
  exit 1
fi

echo -e "${GREEN}✓ Found OpenFHE installation${NC}"

# Set up environment variables
export CGO_CFLAGS="-I${OPENFHE_INSTALL_DIR}/include"
export CGO_LDFLAGS="-L${OPENFHE_INSTALL_DIR}/lib -lOPENFHEbinfhe_static -lOPENFHEcore_static -lOPENFHEpke_static -lstdc++"
export DYLD_LIBRARY_PATH="${OPENFHE_INSTALL_DIR}/lib:${DYLD_LIBRARY_PATH}"

# Parse command line arguments
CMD="${1:-test}"

case "$CMD" in
build)
  echo -e "${BLUE}Building with FHE support...${NC}"
  go build -tags openfhe -o /tmp/test_kbucket .
  echo -e "${GREEN}✓ Build successful!${NC}"
  ;;

test)
  echo -e "${BLUE}Running FHE tests...${NC}"
  go test -tags openfhe -v -run "TestFHE" -timeout 3m
  echo -e "${GREEN}✓ All FHE tests passed!${NC}"
  ;;

test-all)
  echo -e "${BLUE}Running all tests with FHE enabled...${NC}"
  go test -tags openfhe -v -timeout 5m
  echo -e "${GREEN}✓ All tests passed!${NC}"
  ;;

bench)
  echo -e "${BLUE}Running FHE performance benchmarks...${NC}"
  go test -tags openfhe -run=^Bench*$ .
  ;;

example)
  echo -e "${BLUE}Building FHE routing example...${NC}"
  cd examples/fhe_routing
  go build -tags openfhe -o fhe_routing .
  echo -e "${GREEN}✓ Example built successfully!${NC}"
  echo "Run with: ./examples/fhe_routing/fhe_routing"
  ;;

clean)
  echo "Cleaning build artifacts..."
  rm -f /tmp/test_kbucket
  rm -f examples/fhe_routing/fhe_routing
  echo -e "${GREEN}✓ Clean complete${NC}"
  ;;

*)
  echo "Usage: $0 {build|test|test-all|bench|example|clean}"
  echo ""
  echo "Commands:"
  echo "  build     - Build the library with FHE support"
  echo "  test      - Run FHE-specific tests (default)"
  echo "  test-all  - Run all tests with FHE enabled"
  echo "  bench     - Run FHE performance benchmark"
  echo "  example   - Build the FHE routing example"
  echo "  clean     - Remove build artifacts"
  exit 1
  ;;
esac
