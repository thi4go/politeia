// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// userVerifyPaymentCmd checks on the status of the logged in user's
// registration payment.
type userVerifyPaymentCmd struct{}

// Execute executes the verify user payment command.
func (cmd *userVerifyPaymentCmd) Execute(args []string) error {
	vupr, err := client.VerifyUserPayment()
	if err != nil {
		return err
	}
	return shared.PrintJSON(vupr)
}

// userVerifyPaymentHelpMsg is the output of the help command when
// 'userverifypayment' is specified.
var userVerifyPaymentHelpMsg = `userverifypayment 

Check if the currently logged in user has paid their user registration fee.

Arguments: None`
