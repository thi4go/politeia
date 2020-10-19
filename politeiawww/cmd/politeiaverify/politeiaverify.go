package main

import (
	"crypto/ed25519"
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
	PublicKey        string           `json:"publickey"`
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
	MIME    string `json:"mime"`
	Digest  string `json:"digest"`
	Payload string `json:"payload"`
}

type metadata struct {
	Hint    string `json:"hint"`
	Digest  string `json:"digest"`
	Payload string `json:"payload"`
}

func help() {
	fmt.Fprintf(os.Stderr, "usage: politeiaverify [options]\n")
	fmt.Fprintf(os.Stderr, "  <json bundle> - Path to the JSON bundle "+
		"downloaded from the GUI\n")
	fmt.Fprintf(os.Stderr, "\n")
}

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

	}

	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

func _main() error {
	flag.Parse()
	args := flag.Args()

	fmt.Println(args)

	if len(args) != 1 {
		return fmt.Errorf("must provide json bundle as input to the command")
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

	// Compare merkle roots
	merkle := record.CensorshipRecord.Merkle
	m, err := merkleRoot(record.Files, record.Metadata)
	if err != nil {
		return err
	}
	if m != merkle {
		return fmt.Errorf("error calculating merkel %v %v", m, merkle)
	}

	// Decode public key
	key, err := hex.DecodeString(record.PublicKey)
	if err != nil {
		return err
	}
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], key)

	// Decode signature
	sig, err := hex.DecodeString(record.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], sig)

	// Verify record
	token := record.CensorshipRecord.Token
	verified := ed25519.Verify(publicKey[:], []byte(merkle+token), signature[:])

	if !verified {
		return fmt.Errorf("Record verification failed")
	}

	fmt.Println("Record verified successfully")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
