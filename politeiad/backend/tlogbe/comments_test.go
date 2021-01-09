// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/google/uuid"
)

func TestCmdNew(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	settings := []backend.PluginSetting{{
		Key:   pluginSettingDataDir,
		Value: tlogBackend.dataDir,
	}}

	commentsPlugin, err := newCommentsPlugin(tlogBackend,
		newBackendClient(tlogBackend), settings, id)
	if err != nil {
		t.Fatal(err)
	}

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
	invalidParentID := uint32(3)

	uid, err := identity.New()
	if err != nil {
		t.Error(err)
	}

	// Setup new comment plugin tests
	var tests = []struct {
		description string
		payload     comments.New
		wantErr     *backend.PluginUserError
	}{
		{
			"invalid comment state",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateInvalid,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateInvalid,
					rec.Token, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusStateInvalid),
			},
		},
		{
			"invalid token",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     "invalid",
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusTokenInvalid),
			},
		},
		{
			"invalid signature",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: "invalid",
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusSignatureInvalid),
			},
		},
		{
			"invalid public key",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: "invalid",
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusPublicKeyInvalid),
			},
		},
		{
			"comment max length exceeded",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   commentMaxLengthExceeded(t),
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, commentMaxLengthExceeded(t), parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"invalid parent ID",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  invalidParentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, invalidParentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusParentIDInvalid),
			},
		},
		{
			"record not found",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     tokenRandom,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					tokenRandom, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			},
		},
		{
			"success",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, parentID),
			},
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

func TestCmdEdit(t *testing.T) {
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

	commentEdit := comment + "more content"

	parentID := uint32(0)

	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))

	id, err := identity.New()
	if err != nil {
		t.Error(err)
	}

	// New comment
	ncEncoded, err := comments.EncodeNew(
		comments.New{
			UserID:    uuid.New().String(),
			State:     comments.StateUnvetted,
			Token:     rec.Token,
			ParentID:  parentID,
			Comment:   comment,
			PublicKey: id.Public.String(),
			Signature: commentSignature(t, id, comments.StateUnvetted,
				rec.Token, comment, parentID),
		},
	)
	if err != nil {
		t.Error(err)
	}
	reply, err := commentsPlugin.cmdNew(string(ncEncoded))
	if err != nil {
		t.Error(err)
	}
	nr, err := comments.DecodeNewReply([]byte(reply))
	if err != nil {
		t.Error(err)
	}

	// Setup edit comment plugin tests
	var tests = []struct {
		description  string
		token        string
		userID       string
		parentID     uint32
		commentID    uint32
		comment      string
		state        comments.StateT
		badSignature bool
		badPublicKey bool
		wantErr      *backend.PluginUserError
	}{
		{
			"invalid comment state",
			rec.Token,
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateInvalid,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusStateInvalid),
			},
		},
		{
			"invalid token",
			"invalid",
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateUnvetted,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusTokenInvalid),
			},
		},
		{
			"invalid signature",
			rec.Token,
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateUnvetted,
			true,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusSignatureInvalid),
			},
		},
		{
			"invalid public key",
			rec.Token,
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateUnvetted,
			false,
			true,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusPublicKeyInvalid),
			},
		},
		{
			"comment max length exceeded",
			rec.Token,
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			newCommentMaxLengthExceeded(t),
			comments.StateUnvetted,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"comment id not found",
			rec.Token,
			nr.Comment.UserID,
			parentID,
			3,
			commentEdit,
			comments.StateUnvetted,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentNotFound),
			},
		},
		{
			"unauthorized user",
			rec.Token,
			uuid.New().String(),
			parentID,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateUnvetted,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusUserUnauthorized),
			},
		},
		{
			"invalid parent ID",
			rec.Token,
			nr.Comment.UserID,
			3,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateUnvetted,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusParentIDInvalid),
			},
		},
		{
			"comment did not change",
			rec.Token,
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			comment,
			comments.StateUnvetted,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"record not found",
			tokenRandom,
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateUnvetted,
			false,
			false,
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			},
		},
		{
			"success",
			rec.Token,
			nr.Comment.UserID,
			parentID,
			nr.Comment.CommentID,
			commentEdit,
			comments.StateUnvetted,
			false,
			false,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Edit Comment
			ec := editComment(t, test.userID, test.token, test.comment,
				test.commentID, test.parentID, test.state, id)
			if test.badSignature {
				ec.Signature = "bad signature"
			}
			if test.badPublicKey {
				ec.PublicKey = "bad public key"
			}
			ecEncoded, err := comments.EncodeEdit(ec)
			if err != nil {
				t.Error(err)
			}

			// Execute plugin command
			_, err = commentsPlugin.cmdEdit(string(ecEncoded))

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
