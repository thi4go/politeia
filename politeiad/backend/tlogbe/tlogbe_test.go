// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"fmt"
	"testing"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
)

type recordContentTest struct {
	description string
	metadata    []backend.MetadataStream
	files       []backend.File
	filesDel    []string
	err         backend.ContentVerificationError
}

func setupRecordContentTests(t *testing.T) []recordContentTest {
	t.Helper()

	var rct []recordContentTest

	// Invalid metadata ID error
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, v1.MetadataStreamsMax+1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel := []string{}
	err := backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidMDID,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid metadata ID error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Duplicate metadata ID error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateMDID,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate metadata ID error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid filename error
	fs = []backend.File{
		newBackendFile(t, "invalid/filename.md"),
	}
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid filename error",
		metadata:    md,
		files:       fs,
		err:         err,
	})

	// Empty files error
	fs = []backend.File{}
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusEmpty,
	}
	rct = append(rct, recordContentTest{
		description: "Empty files error",
		metadata:    md,
		files:       fs,
		err:         err,
	})

	// Duplicate filename error
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel = []string{}
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate filename error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	return rct
}

func TestNewRecord(t *testing.T) {
	tlogBackend, err := newTestTlogBackend(t)
	if err != nil {
		fmt.Printf("Error in newTestTlogBackend %v", err)
		return
	}

	metadata := backend.MetadataStream{
		ID:      1,
		Payload: "",
	}

	file := backend.File{
		Name:    "index.md",
		MIME:    "text/plain; charset=utf-8",
		Digest:  "22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2",
		Payload: "bW9vCg==",
	}

	rmd, err := tlogBackend.New([]backend.MetadataStream{metadata},
		[]backend.File{file})
	if err != nil {
		fmt.Printf("Error in New %v", err)
		return
	}

	fmt.Println(rmd)
}
