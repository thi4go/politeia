package tlogbe

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrutil/v3"
	v1 "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/types"
	"github.com/robfig/cron"
)

var (
	_ TClient = (*TestTrillianClient)(nil)

	defaultTestDir     = dcrutil.AppDataDir("politeiadtest", false)
	defaultTestDataDir = filepath.Join(defaultTestDir, "data")
)

// TestTrillianClient implements TClient interface and is used for
// testing purposes.
type TestTrillianClient struct {
	sync.RWMutex

	trees  map[int64]*trillian.Tree      // [treeID]Tree
	leaves map[int64][]*trillian.LogLeaf // [treeID][]LogLeaf

	privateKey *keyspb.PrivateKey
}

// tree satisfies the TClient interface. Returns trillian tree from passed in
// ID.
func (t *TestTrillianClient) tree(treeID int64) (*trillian.Tree, error) {
	t.RLock()
	defer t.RUnlock()

	if tree, ok := t.trees[treeID]; ok {
		return tree, nil
	}

	return nil, fmt.Errorf("Tree ID not found")
}

// treesAll satisfies the TClient interface. Signed log roots are not used
// for testing up until now, so we return a nil value for it.
func (t *TestTrillianClient) treesAll() ([]*trillian.Tree, error) {
	t.RLock()
	defer t.RUnlock()

	trees := make([]*trillian.Tree, len(t.trees))
	for _, t := range t.trees {
		trees = append(trees, t)
	}

	return trees, nil
}

// treeNew satisfies the TClient interface. Creates a new trillian tree
// in memory.
func (t *TestTrillianClient) treeNew() (*trillian.Tree, *trillian.SignedLogRoot, error) {
	t.Lock()
	defer t.Unlock()

	// Retrieve private key
	pk, err := ptypes.MarshalAny(t.privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Create trillian tree
	tree := trillian.Tree{
		TreeId:             rand.Int63(),
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      sigpb.DigitallySigned_SHA256,
		SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
		DisplayName:        "",
		Description:        "",
		MaxRootDuration:    ptypes.DurationProto(0),
		PrivateKey:         pk,
	}
	t.trees[tree.TreeId] = &tree

	// Initialize leaves map for that tree
	t.leaves[tree.TreeId] = []*trillian.LogLeaf{}

	return &tree, nil, nil
}

// leavesAppend satisfies the TClient interface. It appends leaves to the
// corresponding trillian tree in memory.
func (t *TestTrillianClient) leavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]QueuedLeafProof, *types.LogRootV1, error) {
	t.Lock()
	defer t.Unlock()

	// Get last leaf index
	var index int64
	if len(t.leaves[treeID]) > 0 {
		l := len(t.leaves[treeID])
		index = t.leaves[treeID][l-1].LeafIndex + 1
	} else {
		index = 0
	}

	// Set merkle hash for each leaf and append to memory. Also append the
	// queued value for the leaves to be returned by the function.
	var queued []QueuedLeafProof
	for _, l := range leaves {
		l.LeafIndex = index
		l.MerkleLeafHash = MerkleLeafHash(l.LeafValue)
		t.leaves[treeID] = append(t.leaves[treeID], l)

		queued = append(queued, QueuedLeafProof{
			QueuedLeaf: &trillian.QueuedLogLeaf{
				Leaf:   l,
				Status: nil,
			},
			Proof: nil,
		})
	}

	return queued, nil, nil
}

// leavesAll satisfies the TClient interface. Returns all leaves from a
// trillian tree.
func (t *TestTrillianClient) leavesAll(treeID int64) ([]*trillian.LogLeaf, error) {
	t.RLock()
	defer t.RUnlock()

	// Check if treeID entry exists
	if _, ok := t.leaves[treeID]; !ok {
		return nil, fmt.Errorf("Tree ID %d does not contain any leaf data",
			treeID)
	}

	return t.leaves[treeID], nil
}

// leavesByRange satisfies the TClient interface. Returns leaves in range
// according to the passed in parameters.
func (t *TestTrillianClient) leavesByRange(treeID, startIndex, count int64) ([]*trillian.LogLeaf, error) {
	t.RLock()
	defer t.RUnlock()

	// Check if treeID entry exists
	if _, ok := t.leaves[treeID]; !ok {
		return nil, fmt.Errorf("Tree ID %d does not contain any leaf data",
			treeID)
	}

	// Get leaves by range. Indexes are ordered.
	var c int64
	var leaves []*trillian.LogLeaf
	for _, leaf := range t.leaves[treeID] {
		if leaf.LeafIndex >= startIndex && c < count {
			leaves = append(leaves, leaf)
			c++
		}
	}

	return nil, nil
}

// signedLogRootForTree is a stub to satisfy the TClient interface. It is not
// used for testing.
func (t *TestTrillianClient) signedLogRootForTree(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	return nil, nil, nil
}

// close is a stub to satisfy the TClient interface. It is not used for
// testing.
func (t *TestTrillianClient) close() {
	return
}

// newTestTrillianClient provides a trillian client implementation used for
// testing. It implements the TClient interface, which includes all major
// tree operations used in the tlog backend.
func newTestTrillianClient(t *testing.T) (*TestTrillianClient, error) {
	// Create trillian private key
	key, err := keys.NewFromSpec(&keyspb.Specification{
		Params: &keyspb.Specification_EcdsaParams{},
	})
	if err != nil {
		return nil, err
	}
	keyDer, err := der.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}

	ttc := TestTrillianClient{
		trees:  make(map[int64]*trillian.Tree),
		leaves: make(map[int64][]*trillian.LogLeaf),
		privateKey: &keyspb.PrivateKey{
			Der: keyDer,
		},
	}

	return &ttc, nil
}

// newTestTlog returns a tlog used for testing.
func newTestTlog(t *testing.T, id string) (*tlog, error) {
	// Setup key-value store with test dir
	fp := filepath.Join(defaultTestDataDir, id)
	err := os.MkdirAll(fp, 0700)
	if err != nil {
		return nil, err
	}
	store := filesystem.New(fp)

	tclient, err := newTestTrillianClient(t)
	if err != nil {
		return nil, err
	}

	tlog := tlog{
		id:            id,
		dcrtimeHost:   v1.DefaultTestnetTimeHost,
		encryptionKey: nil,
		trillian:      tclient,
		store:         store,
		cron:          cron.New(),
	}

	return &tlog, nil
}

// newTestTlogBackend returns a tlog backend for testing. It wraps
// tlog and trillian client, providing the framework needed for
// writing tlog backend tests.
func newTestTlogBackend(t *testing.T) (*tlogBackend, error) {
	tlogVetted, err := newTestTlog(t, "vetted")
	if err != nil {
		return nil, err
	}
	tlogUnvetted, err := newTestTlog(t, "unvetted")
	if err != nil {
		return nil, err
	}

	tlogBackend := tlogBackend{
		homeDir:       defaultTestDir,
		dataDir:       defaultTestDataDir,
		unvetted:      tlogUnvetted,
		vetted:        tlogVetted,
		plugins:       make(map[string]plugin),
		prefixes:      make(map[string][]byte),
		vettedTreeIDs: make(map[string]int64),
		inv: recordInventory{
			unvetted: make(map[backend.MDStatusT][]string),
			vetted:   make(map[backend.MDStatusT][]string),
		},
	}

	err = tlogBackend.setup()
	if err != nil {
		return nil, fmt.Errorf("setup: %v", err)
	}

	return &tlogBackend, nil
}
