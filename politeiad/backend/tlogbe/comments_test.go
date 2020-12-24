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

	// Setup new comment plugin tests
	var tests = []struct {
		description  string
		token        string
		comment      string
		state        comments.StateT
		parentID     uint32
		badSignature bool
		badPublicKey bool
		wantErr      *backend.PluginUserError
	}{
		{
			"wrong comment state",
			rec.Token,
			comment,
			comments.StateInvalid,
			0,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusStateInvalid),
			},
		},
		{
			"invalid token",
			"invalid",
			comment,
			comments.StateUnvetted,
			0,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusTokenInvalid),
			},
		},
		{
			"invalid signature",
			rec.Token,
			comment,
			comments.StateUnvetted,
			0,
			true,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusSignatureInvalid),
			},
		},
		{
			"invalid public key",
			rec.Token,
			comment,
			comments.StateUnvetted,
			0,
			false,
			true,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusPublicKeyInvalid),
			},
		},
		{
			"comment max length exceeded",
			rec.Token,
			newCommentMaxLengthExceeded(t),
			comments.StateUnvetted,
			0,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"invalid parent ID",
			rec.Token,
			comment,
			comments.StateUnvetted,
			1,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusParentIDInvalid),
			},
		},
		{
			"record not found",
			tokenRandom,
			comment,
			comments.StateUnvetted,
			0,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			},
		},
		{
			"success",
			rec.Token,
			comment,
			comments.StateUnvetted,
			0,
			false,
			false,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// New Comment
			nc := newComment(t, test.token, test.comment, test.state,
				test.parentID)
			if test.badSignature {
				nc.Signature = "bad signature"
			}
			if test.badPublicKey {
				nc.PublicKey = "bad public key"
			}
			ncEncoded, err := comments.EncodeNew(nc)
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
