// Copyright (c) 2020 The Decred developers
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
	"github.com/decred/politeia/politeiad/plugins/pi"
)

func TestCmdCommentNew(t *testing.T) {
	piPlugin, tlogBackend, cleanup := newTestPiPlugin(t)
	defer cleanup()

	// Register comments plugin
	settings := []backend.PluginSetting{{
		Key:   pluginSettingDataDir,
		Value: tlogBackend.dataDir,
	}}
	id, err := identity.New()
	if err != nil {
		t.Error(err)
	}
	tlogBackend.RegisterPlugin(backend.Plugin{
		ID:       comments.ID,
		Version:  comments.Version,
		Settings: settings,
		Identity: id,
	})

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

	// test case: record not found
	recordNotFound := newComment(t, tokenRandom, comment,
		comments.StateUnvetted, parentID)

	// test case: success
	success := newComment(t, rec.Token, comment, comments.StateUnvetted,
		parentID)

	// Setup comment new pi plugin tests
	var tests = []struct {
		description string
		payload     comments.New
		wantErr     *backend.PluginUserError
	}{
		{
			"invalid comment state",
			invalidCommentState,
			&backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropStateInvalid),
			},
		},
		{
			"invalid token",
			invalidToken,
			&backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropTokenInvalid),
			},
		},
		{
			"record not found",
			recordNotFound,
			&backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropNotFound),
			},
		},
		// TODO: bad vote status test case. waiting on plugin architecture
		// refactor
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
			_, err = piPlugin.commentNew(string(ncEncoded))

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
