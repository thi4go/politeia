package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/util"
)

type record struct {
	ServerPublicKey  string           `josn:"serverpublickey"`
	PublicKey        string           `json:"publickey"`
	Signature        string           `json:"signature"`
	CensorshipRecord censorshipRecord `json:"censorshiprecord`
	Files            []files          `json:"files"`
	Metadata         []metadata       `json:"metadata"`
}

type censorshipRecord struct {
	Token     string `json:"token"`
	Merkle    string `json:"merkle"`
	Signature string `json:"signature"`
}

type files struct {
	Name    string `json:"name"`
	Digest  string `json:"digest"`
	Payload string `json:"payload"`
}

type metadata struct {
	Hint    string `json:"hint"`
	Digest  string `json:"digest"`
	Payload string `json:"payload"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiaverify <bundle>\n")
	fmt.Fprintf(os.Stderr, "  <bundle> - Path to the JSON bundle "+
		"downloaded from the GUI\n")
	fmt.Fprintf(os.Stderr, "\n")
}

// merkleRoot calculates the merkle root of a record. It also compares the
// received digest from the input, and digests calculated from their payload.
func merkleRoot(fs []files, mds []metadata) (string, error) {
	digests := make([]*[sha256.Size]byte, 0, len(fs))

	// Files digests
	for _, f := range fs {
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return "", err
		}
		d := util.Digest(b)
		var sha [sha256.Size]byte
		copy(sha[:], d)
		digests = append(digests, &sha)

		// Verify digest
		cd, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return "", fmt.Errorf("invalid digest %v", f.Digest)
		}
		if !bytes.Equal(d, cd[:]) {
			return "", fmt.Errorf("file: %v digests do not match", f.Name)
		}
	}

	// Metadata digests
	for _, md := range mds {
		b, err := base64.StdEncoding.DecodeString(md.Payload)
		if err != nil {
			return "", err
		}
		d := util.Digest(b)
		var sha [sha256.Size]byte
		copy(sha[:], d)
		digests = append(digests, &sha)

		// Verify digest
		cd, ok := util.ConvertDigest(md.Digest)
		if !ok {
			return "", fmt.Errorf("invalid digest %v", md.Digest)
		}
		if !bytes.Equal(d, cd[:]) {
			return "", fmt.Errorf("metadata: %v digests do not match", md.Hint)
		}
	}

	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

func _main() error {
	flag.Parse()
	args := flag.Args()

	if len(args) != 1 {
		usage()
		return fmt.Errorf("Must provide json bundle as input to the command")
	}

	var payload []byte
	payload, err := ioutil.ReadFile(args[0])
	if err != nil {
		return err
	}

	var record record
	err = json.Unmarshal(payload, &record)
	if err != nil {
		return err
	}

	// Verify merkle root
	merkle := record.CensorshipRecord.Merkle
	m, err := merkleRoot(record.Files, record.Metadata)
	if err != nil {
		return err
	}
	if m != merkle {
		return fmt.Errorf("Merkle roots do not match: %v and %v", m, merkle)
	}

	// Verify record signature
	id, err := util.IdentityFromString(record.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(record.Signature)
	if !id.VerifyMessage([]byte(merkle), sig) {
		return fmt.Errorf("Invalid record signature %v", record.Signature)
	}

	// Verify censorship record signature
	id, err = util.IdentityFromString(record.ServerPublicKey)
	if err != nil {
		return err
	}
	sig, err = util.ConvertSignature(record.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	if !id.VerifyMessage([]byte(merkle+record.CensorshipRecord.Token), sig) {
		return fmt.Errorf("Invalid censhorship record signature %v",
			record.CensorshipRecord.Signature)
	}

	fmt.Println("Record successfully verified")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
