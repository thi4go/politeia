// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

// ProposalInventoryCmd retrieves the censorship record tokens of all proposals in
// the inventory.
type ProposalInventoryCmd struct{}

// Execute executes the proposal inventory command.
func (cmd *ProposalInventoryCmd) Execute(args []string) error {
	reply, err := client.ProposalInventory()
	if err != nil {
		return err
	}

	return PrintJSON(reply)
}

// ProposalInventoryHelpMsg is the output of the help command when
// 'proposalinventory' is specified.
const ProposalInventoryHelpMsg = `proposalinventory

Fetch the censorship record tokens for all proposals, separated by their
status. The unvetted tokens is only returned if the logged in user is an
admin.

Arguments:
None

Response:
{
  "unvetted": 	[(string)] List of unvetted proposal tokens
  "public": 	[(string)] List of public proposal tokens
  "censored":	[(string)] List of censored proposal tokens
  "abandoned": 	[(string)] List of abandoned proposal tokens
}`
