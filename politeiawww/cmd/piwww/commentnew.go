// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"strconv"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// commentNewCmd submits a new proposal comment.
type commentNewCmd struct {
	Args struct {
		Token    string `positional-arg-name:"token" required:"true"`   // Censorship token
		Comment  string `positional-arg-name:"comment" required:"true"` // Comment text
		ParentID string `positional-arg-name:"parentID"`                // Comment parent ID
	} `positional-args:"true"`

	// CLI flags
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the new comment command.
func (cmd *commentNewCmd) Execute(args []string) error {
	token := cmd.Args.Token
	comment := cmd.Args.Comment
	parentID := cmd.Args.ParentID

	// Verify state. Defaults to vetted if the --unvetted flag
	// is not used.
	var state pi.PropStateT
	switch {
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	default:
		state = pi.PropStateVetted
	}

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup new comment request
	sig := cfg.Identity.SignMessage([]byte(string(state) + token + parentID +
		comment))
	// Parse provided parent id
	piUint, err := strconv.ParseUint(parentID, 10, 32)
	if err != nil {
		return err
	}
	cn := pi.CommentNew{
		Token:     token,
		State:     state,
		ParentID:  uint32(piUint),
		Comment:   comment,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err = shared.PrintJSON(cn)
	if err != nil {
		return err
	}

	// Send request
	ncr, err := client.CommentNew(cn)
	if err != nil {
		return err
	}

	// Print response details
	return shared.PrintJSON(ncr)
}

// commentNewHelpMsg is the output of the help command when 'commentnew' is
// specified.
const commentNewHelpMsg = `commentnew "token" "comment"

Comment on a vetted record as logged in user.

Arguments:
1. token       (string, required)   Proposal censorship token
2. comment     (string, required)   Comment
3. parentID    (string, required if replying to comment)  Id of commment

Flags:
  --unvetted   (bool, optional)    Comment on unvetted record.
`
