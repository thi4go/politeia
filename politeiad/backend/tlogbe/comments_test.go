// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/plugins/comments"
)

func TestCmdNew(t *testing.T) {
	commentsPlugin, tlogBackend, cleanup := newTestCommentsPlugin(t)
	defer cleanup()

	// New record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}

	// Helpers
	comment := "random comment"
	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))
	parentID := uint32(0)

	// test case: invalid comment state
	invalidCommentState := newComment(t, rec.Token, comment,
		comments.StateInvalid, parentID)

	// test case: invalid token
	invalidToken := newComment(t, "invalid", comment, comments.StateUnvetted,
		parentID)

	// test case: invalid signature
	invalidSig := newComment(t, rec.Token, comment, comments.StateUnvetted,
		parentID)
	invalidSig.Signature = "bad sig"

	// test case: invalid public key
	invalidPk := newComment(t, rec.Token, comment, comments.StateUnvetted,
		parentID)
	invalidPk.PublicKey = "bad pk"

	// test case: comment max length exceeded
	invalidLength := newComment(t, rec.Token, newCommentMaxLengthExceeded(t),
		comments.StateUnvetted, parentID)

	// test case: invalid parent ID
	invalidParentID := newComment(t, rec.Token, comment,
		comments.StateUnvetted, 3)

	// test case: record not found
	recordNotFound := newComment(t, tokenRandom, comment,
		comments.StateUnvetted, parentID)

	// test case: success
	success := newComment(t, rec.Token, comment, comments.StateUnvetted,
		parentID)

	// Setup new comment plugin tests
	var tests = []struct {
		description string
		payload     comments.New
		wantErr     *backend.PluginUserError
	}{
		{
			"invalid comment state",
			invalidCommentState,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusStateInvalid),
			},
		},
		{
			"invalid token",
			invalidToken,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusTokenInvalid),
			},
		},
		{
			"invalid signature",
			invalidSig,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusSignatureInvalid),
			},
		},
		{
			"invalid public key",
			invalidPk,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusPublicKeyInvalid),
			},
		},
		{
			"comment max length exceeded",
			invalidLength,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"invalid parent ID",
			invalidParentID,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusParentIDInvalid),
			},
		},
		{
			"record not found",
			recordNotFound,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			},
		},
		{
			"success",
			success,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// New Comment
			ncEncoded, err := comments.EncodeNew(test.payload)
			if err != nil {
				t.Error(err)
			}

			// Execute plugin command
			_, err = commentsPlugin.cmdNew(string(ncEncoded))

			// Parse plugin user error
			var pluginUserError backend.PluginUserError
			if errors.As(err, &pluginUserError) {
				if test.wantErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if pluginUserError.ErrorCode != test.wantErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						pluginUserError.ErrorCode,
						test.wantErr.ErrorCode)
				}

				return
			}

			// Expecting nil err
			if err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}
}
