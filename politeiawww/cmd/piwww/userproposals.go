// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// userProposalsCmd gets the proposals for the specified user.
type userProposalsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userID"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the user proposals command.
func (cmd *userProposalsCmd) Execute(args []string) error {
	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get user proposals
	upr, err := client.UserProposals(
		&v1.UserProposals{
			UserId: cmd.Args.UserID,
		})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range upr.Proposals {
		err := shared.VerifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print user proposals
	return shared.PrintJSON(upr)
}

// userProposalsHelpMsg is the output of the help command when 'userproposals'
// is specified.
const userProposalsHelpMsg = `userproposals "userID" 

Fetch all proposals submitted by a specific user.

Arguments:
1. userID      (string, required)   User id`
