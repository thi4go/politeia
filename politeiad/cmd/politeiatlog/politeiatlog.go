package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/sharedconfig"
	"github.com/google/trillian"
)

const (
	defaultTrillianHostUnvetted = "localhost:8090"
	defaultTrillianHostVetted   = "localhost:8094"
	defaultTrillianKeyUnvetted  = "unvetted-trillian.key"
	defaultTrillianKeyVetted    = "vetted-trillian.key"
)

var (
	defaultHomeDir = sharedconfig.DefaultHomeDir

	flagTrillian = flag.String("trillian", "", "Trillian database name "+
		"(vetted/unvetted)")

	tclient *tlogbe.TrillianClient
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiatlog [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	fmt.Fprintf(os.Stderr, "  tree <treeID>  - Retrieve trillian tree "+
		"<treeID>\n")
	fmt.Fprintf(os.Stderr, "  leaves         - Retrieve trillian tree leaves "+
		"<treeID>\n")
	fmt.Fprintf(os.Stderr, "  leavesByRange  - Retrieve trillian tree leaves "+
		"by range\n")
	fmt.Fprintf(os.Stderr, "  new               - Create new record "+
		"[metadata<id>]... <filename>...\n")
	fmt.Fprintf(os.Stderr, "  getunvetted       - Retrieve record "+
		"<id>\n")

	fmt.Fprintf(os.Stderr, "\n")
}

func printTree(tree *trillian.Tree) {
	fmt.Printf("TreeID            : %v\n", tree.TreeId)
	fmt.Printf("TreeState         : %v\n", tree.TreeState)
	fmt.Printf("TreeType          : %v\n", tree.TreeType)
	fmt.Printf("HashStrategy      : %v\n", tree.HashStrategy)
	fmt.Printf("HashAlgorithm     : %v\n", tree.HashAlgorithm)
	fmt.Printf("SignatureAlgorithm: %v\n", tree.SignatureAlgorithm)
	fmt.Printf("DisplayName       : %v\n", tree.DisplayName)
	fmt.Printf("Description       : %v\n", tree.Description)
	fmt.Printf("PublicKey         : %v\n", tree.PublicKey)
	fmt.Printf("MaxRootDuration   : %v\n", tree.MaxRootDuration)
	fmt.Printf("CreateTime        : %v\n", tree.CreateTime)
	fmt.Printf("UpdateTime        : %v\n", tree.UpdateTime)
	fmt.Printf("Deleted           : %v\n", tree.Deleted)
	fmt.Printf("DeleteTime        : %v\n", tree.DeleteTime)
}

func printLeaf(leaf *trillian.LogLeaf) {
	fmt.Printf("MerkleLeafHash    : %x\n", leaf.MerkleLeafHash)
	fmt.Printf("LeafValue         : %x\n", leaf.LeafValue)
	fmt.Printf("ExtraData         : %s\n", leaf.ExtraData)
	fmt.Printf("LeafIndex         : %v\n", leaf.LeafIndex)
	fmt.Printf("LeafIdentityHash  : %x\n", leaf.LeafIdentityHash)
	fmt.Printf("QueueTimestamp    : %v\n", leaf.QueueTimestamp)
	fmt.Printf("IntegrateTimestamp: %v\n", leaf.IntegrateTimestamp)
}

func tree() error {
	treeID, err := strconv.ParseInt(flag.Args()[1], 10, 64)
	if err != nil {
		return err
	}

	tree, err := tclient.Tree(treeID)
	if err != nil {
		return fmt.Errorf("Tree ID %v not found on %v database",
			treeID, *flagTrillian)
	}

	printTree(tree)

	return nil
}

func leavesAll() error {
	treeID, err := strconv.ParseInt(flag.Args()[1], 10, 64)
	if err != nil {
		return err
	}

	leaves, err := tclient.LeavesAll(treeID)
	if err != nil {
		return err
	}

	fmt.Printf("TreeID: %v\n", treeID)
	for _, leaf := range leaves {
		printLeaf(leaf)
	}
	if len(leaves) == 0 {
		fmt.Printf("Tree has no leaves")
	}

	return nil
}

func leavesByRange() error {
	args := flag.Args()[1:]

	if len(args) != 3 {
		usage()
		return fmt.Errorf("Must pass in all required arguments")
	}

	treeID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}
	startIndex, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}
	count, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}

	leaves, err := tclient.LeavesByRange(treeID, startIndex, count)
	if err != nil {
		return err
	}

	fmt.Printf("TreeID    : %v\n", treeID)
	fmt.Printf("StartIndex: %v\n", startIndex)
	fmt.Printf("Count     : %v\n", count)
	for _, leaf := range leaves {
		printLeaf(leaf)
	}
	if len(leaves) == 0 {
		fmt.Printf("Tree has no leaves")
	}

	return nil
}

func _main() error {
	flag.Parse()

	args := flag.Args()

	// Validate arguments
	switch {
	case len(args) == 0:
		usage()
		return fmt.Errorf("Must provide command action")
	case *flagTrillian == "":
		usage()
		return fmt.Errorf("Must provide the trillian database name")
	}

	// Set tlog client
	var host, key string
	switch *flagTrillian {
	case "unvetted":
		host = defaultTrillianHostUnvetted
		key = filepath.Join(defaultHomeDir, defaultTrillianKeyUnvetted)
	case "vetted":
		host = defaultTrillianHostVetted
		key = filepath.Join(defaultHomeDir, defaultTrillianKeyVetted)
	}
	tc, err := tlogbe.NewTrillianClient(host, key)
	if err != nil {
		return err
	}
	tclient = tc

	// Parse action
	switch args[0] {
	case "tree":
		return tree()
	case "leaves":
		return leavesAll()
	case "leavesByRange":
		return leavesByRange()
	default:
		usage()
		return fmt.Errorf("Must choose a valid action")
	}
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
