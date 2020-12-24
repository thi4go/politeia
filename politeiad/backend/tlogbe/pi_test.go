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

	// Setup comment new pi plugin tests
	var tests = []struct {
		description string
		token       string
		comment     string
		state       comments.StateT
		parentID    uint32
		wantErr     *backend.PluginUserError
	}{
		{
			"wrong comment state",
			rec.Token,
			comment,
			comments.StateInvalid,
			0,
			&backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropStateInvalid),
			},
		},
		{
			"invalid token",
			"invalid",
			comment,
			comments.StateUnvetted,
			0,
			&backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropTokenInvalid),
			},
		},
		{
			"record not found",
			tokenRandom,
			comment,
			comments.StateUnvetted,
			0,
			&backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropNotFound),
			},
		},
		// TODO: bad vote status test case. waiting on plugin architecture
		// refactor
		{
			"success",
			rec.Token,
			comment,
			comments.StateUnvetted,
			0,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// New Comment
			nc := newComment(t, test.token, test.comment, test.state,
				test.parentID)
			ncEncoded, err := comments.EncodeNew(nc)
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
