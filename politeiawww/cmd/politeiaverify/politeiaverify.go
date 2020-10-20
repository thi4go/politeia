package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
)

type proposal struct {
	PublicKey        string              `json:"publickey"`
	Signature        string              `json:"signature"`
	CensorshipRecord pi.CensorshipRecord `json:"censorshiprecord"`
	Files            []pi.File           `json:"files"`
	Metadata         []pi.Metadata       `json:"metadata"`
	ServerPublicKey  string              `json:"serverpublickey"`
}

type comments []struct {
	CommentID       string `json:"commentid"`
	Receipt         string `json:"receipt"`
	Signature       string `json:"signature"`
	ServerPublicKey string `json:"serverpublickey"`
}

var (
	flagVerifyProposal = flag.Bool("proposal", false, "Verify proposal bundle")
	flagVerifyComments = flag.Bool("comments", false, "Verify comments bundle")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiaverify [flags] <bundle>\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, " <bundle> - Path to the JSON bundle "+
		"downloaded from the GUI\n")
	fmt.Fprintf(os.Stderr, "\n")
}

func verifyProposal(payload []byte) error {
	var prop proposal
	err := json.Unmarshal(payload, &prop)
	if err != nil {
		return err
	}

	// Verify merkle root
	merkle, err := wwwutil.MerkleRoot(prop.Files, prop.Metadata)
	if err != nil {
		return err
	}
	if merkle != prop.CensorshipRecord.Merkle {
		return fmt.Errorf("Merkle roots do not match: %v and %v",
			prop.CensorshipRecord.Merkle, merkle)
	}

	// Verify proposal signature
	id, err := util.IdentityFromString(prop.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(prop.Signature)
	if err != nil {
		return err
	}
	if !id.VerifyMessage([]byte(merkle), sig) {
		return fmt.Errorf("Invalid proposal signature %v", prop.Signature)
	}

	// Verify censorship record signature
	id, err = util.IdentityFromString(prop.ServerPublicKey)
	if err != nil {
		return err
	}
	sig, err = util.ConvertSignature(prop.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	if !id.VerifyMessage([]byte(merkle+prop.CensorshipRecord.Token), sig) {
		return fmt.Errorf("Invalid censhorship record signature %v",
			prop.CensorshipRecord.Signature)
	}

	fmt.Println("Proposal successfully verified")

	return nil
}

func verifyComments(payload []byte) error {
	var comments comments
	err := json.Unmarshal(payload, &comments)
	if err != nil {
		return err
	}

	for _, c := range comments {
		// Verify receipt
		id, err := util.IdentityFromString(c.ServerPublicKey)
		if err != nil {
			return err
		}
		receipt, err := util.ConvertSignature(c.Receipt)
		if err != nil {
			return err
		}
		if !id.VerifyMessage([]byte(c.Signature), receipt) {
			return fmt.Errorf("Could not verify receipt %v of comment id %v",
				c.Receipt, c.CommentID)
		}
	}

	fmt.Println("Comments successfully verified")

	return nil
}

func _main() error {
	flag.Parse()
	args := flag.Args()

	// Validate flags and arguments
	switch {
	case len(args) != 1:
		usage()
		return fmt.Errorf("Must provide json bundle path as input")
	case *flagVerifyProposal && *flagVerifyComments:
		usage()
		return fmt.Errorf("Must choose only one verification type")
	case !*flagVerifyProposal && !*flagVerifyComments:
		usage()
		return fmt.Errorf("Must choose at least one verification type")
	}

	// Read bundle payload
	var payload []byte
	payload, err := ioutil.ReadFile(args[0])
	if err != nil {
		return err
	}

	// Call verify method
	switch {
	case *flagVerifyProposal:
		err = verifyProposal(payload)
	case *flagVerifyComments:
		err = verifyComments(payload)
	}

	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
