// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

func createValidLineItems(t *testing.T) []cms.LineItemsInput {
	t.Helper()

	return []cms.LineItemsInput{
		{
			Type:          cms.LineItemTypeLabor,
			Domain:        "Development",
			Subdomain:     "politeia",
			Description:   "PR #1",
			ProposalToken: "",
			Labor:         40,
			Expenses:      0,
		},
		{
			Type:          cms.LineItemTypeExpense,
			Domain:        "Design",
			Subdomain:     "pgui",
			Description:   "Artwork",
			ProposalToken: "",
			Labor:         0,
			Expenses:      1000,
		},
		{
			Type:          cms.LineItemTypeMisc,
			Domain:        "Research",
			Subdomain:     "dcrd",
			Description:   "reorg",
			ProposalToken: "",
			Labor:         0,
			Expenses:      10000,
		},
	}
}

func createInvoiceInput(t *testing.T, li []cms.LineItemsInput) cms.InvoiceInput {
	t.Helper()

	return cms.InvoiceInput{
		Version:            1,
		Month:              2,
		Year:               2019,
		ExchangeRate:       1651,
		ContractorName:     "test",
		ContractorLocation: "testlocation",
		ContractorContact:  "test@gmail.com",
		ContractorRate:     4000,
		PaymentAddress:     "DsUHkmH555D4tLQi5ap4gVAV86tVN29nqYi",
		LineItems:          li,
	}
}

// createInvoiceJSON creates an index file with the passed InvoiceInput
func createInvoiceJSON(t *testing.T, ii cms.InvoiceInput) *www.File {
	t.Helper()

	file, _ := json.Marshal(ii)

	return &www.File{
		Name:    invoiceFile,
		MIME:    mime.DetectMimeType(file),
		Digest:  hex.EncodeToString(util.Digest(file)),
		Payload: base64.StdEncoding.EncodeToString(file),
	}
}

// createNewInvoice computes the merkle root of the given files, signs the
// merkle root with the given identity then returns a NewInvoice object.
func createNewInvoice(t *testing.T, id *identity.FullIdentity, files []www.File, month uint, year uint) *cms.NewInvoice {
	t.Helper()

	if len(files) == 0 {
		t.Fatalf("no files found")
	}

	// Compute merkle
	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, f := range files {
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			t.Fatalf("could not convert digest %v", f.Digest)
		}
		digests = append(digests, &d)
	}
	root := hex.EncodeToString(merkle.Root(digests)[:])

	// Sign merkle
	sig := id.SignMessage([]byte(root))

	return &cms.NewInvoice{
		Month:     month,
		Year:      year,
		Files:     files,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}
}

// Invoice Validation Tests
func TestValidateInvoice(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t, cmsWWWMode)
	defer cleanup()

	usr, id := newUser(t, p, true, false)

	vli := createValidLineItems(t)
	ii := createInvoiceInput(t, vli)
	json := createInvoiceJSON(t, ii)
	png := createFilePNG(t, false)
	md := newFileRandomMD(t)
	ni := createNewInvoice(t, id, []www.File{*json, *png}, ii.Month, ii.Year)

	// Invalid signature test
	invoiceInvalidSig := cms.NewInvoice{
		Month:     ni.Month,
		Year:      ni.Year,
		Files:     ni.Files,
		PublicKey: ni.PublicKey,
		Signature: "invalid",
	}

	// No file test
	invoiceNoFiles := cms.NewInvoice{
		Month:     ni.Month,
		Year:      ni.Year,
		Files:     make([]www.File, 0),
		PublicKey: ni.PublicKey,
		Signature: ni.Signature,
	}

	// Invalid index mime type test
	indexJpeg := createFileJPEG(t, invoiceFile)
	invoiceInvalidIndexMimeType := createNewInvoice(t, id,
		[]www.File{*indexJpeg}, ii.Month, ii.Year)

	// No index file test
	invoiceNoIndexFile := createNewInvoice(t, id,
		[]www.File{*png}, ii.Month, ii.Year)

	// Too many index files test
	invoiceMaxIndexFiles := createNewInvoice(t, id, []www.File{*json, *json},
		ii.Month, ii.Year)

	// Too many attached files test
	files := make([]www.File, 0, cms.PolicyMaxAttachments+1)
	files = append(files, *json)
	for i := 0; i < cms.PolicyMaxAttachments+1; i++ {
		m := md
		m.Name = fmt.Sprintf("%v.md", i)
		files = append(files, m)
	}
	invoiceMaxAttachments := createNewInvoice(t, id, files, ii.Month, ii.Year)

	// Index file too large test.
	// It creates a valid line item input, but too large to be accepted
	lineItemLabor := cms.LineItemsInput{
		Type:          cms.LineItemTypeLabor,
		Domain:        "Development",
		Subdomain:     "politeia",
		Description:   "PR #2",
		ProposalToken: "",
		Labor:         20,
		Expenses:      0,
	}
	tooManyLineItems := make([]cms.LineItemsInput, 0, 5000)
	for i := 0; i < 5000; i++ {
		tooManyLineItems = append(tooManyLineItems, lineItemLabor)
	}
	invalidInvoiceInput := createInvoiceInput(t, tooManyLineItems)
	jsonLarge := createInvoiceJSON(t, invalidInvoiceInput)
	invoiceIndexLarge := createNewInvoice(t, id, []www.File{*jsonLarge},
		ii.Month, ii.Year)

	// Attachment file too large test
	fileLarge := createFilePNG(t, true)
	invoiceAttachmentLarge := createNewInvoice(t, id,
		[]www.File{*json, *fileLarge}, ii.Month, ii.Year)

	// Files with duplicate payload test
	pngDuplicatePayload := www.File{
		Name:    "otherpng.png",
		MIME:    png.MIME,
		Digest:  png.Digest,
		Payload: png.Payload,
	}
	invoiceDuplicatePayload := createNewInvoice(t, id,
		[]www.File{*json, *png, pngDuplicatePayload}, ii.Month, ii.Year)

	// Incorrect signature test
	invoiceIncorrectSig := createNewInvoice(t, id, []www.File{*json},
		ii.Month, ii.Year)
	invoiceIncorrectSig.Signature = ni.Signature

	// Setup test cases
	// XXX this only adds partial test coverage to validateInvoice
	var tests = []struct {
		name       string
		newInvoice cms.NewInvoice
		user       *user.User
		want       error
	}{
		{"correct invoice", *ni, usr, nil},

		{"invalid signature", invoiceInvalidSig, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},

		{"no files", invoiceNoFiles, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalMissingFiles,
			}},

		{"invalid index mime type", *invoiceInvalidIndexMimeType, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidIndexFileMimeType,
			}},

		{"no index files", *invoiceNoIndexFile, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusNoIndexFile,
			}},

		{"too many index files", *invoiceMaxIndexFiles, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxIndexFileExceeded,
			}},

		{"too many attached files", *invoiceMaxAttachments, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxAttachmentsExceeded,
			}},

		{"index file too large", *invoiceIndexLarge, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxIndexFileSizeExceeded,
			}},

		{"attachment file too large", *invoiceAttachmentLarge, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxAttachmentSizeExceeded,
			}},

		{"duplicate file payloads", *invoiceDuplicatePayload, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicateFilePayloads,
			}},

		{"incorrect signature", *invoiceIncorrectSig, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := p.validateInvoice(test.newInvoice, test.user)
			got := errToStr(err)
			want := errToStr(test.want)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}
