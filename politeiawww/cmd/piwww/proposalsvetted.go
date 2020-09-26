// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// proposalsVettedCmd retreives a page of vetted proposals.
type proposalsVettedCmd struct {
	Before string `long:"before"` // Before censorship token
	After  string `long:"after"`  // After censorship token
}

// Execute executs the vetted proposals command.
func (cmd *proposalsVettedCmd) Execute(args []string) error {
	if cmd.Before != "" && cmd.After != "" {
		return fmt.Errorf("the 'before' and 'after' flags " +
			"cannot be used at the same time")
	}

	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get a page of vetted proposals
	gavr, err := client.GetAllVetted(&v1.GetAllVetted{
		Before: cmd.Before,
		After:  cmd.After,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range gavr.Proposals {
		err = shared.VerifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print vetted proposals
	return shared.PrintJSON(gavr)
}

// proposalsVettedHelpMsg is the output for the help command when
// 'proposalsvetted' is specified.
const proposalsVettedHelpMsg = `proposalsvetted [flags]

Fetch a page of vetted proposals. 

Arguments: None

Flags:
  --before     (string, optional)   Get proposals before this proposal (token)
  --after      (string, optional)   Get proposals after this proposal (token)

Example:
getvetted --after=[token]`
