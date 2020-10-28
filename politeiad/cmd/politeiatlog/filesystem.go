package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

// This tool is assuming that the store is a fileSystem for now. Politeiatlog
// will have cert flags later on for connecting to a SQL database.
//
// fileSystem implements the Blob interface.
type fileSystem struct {
	sync.RWMutex
	root string
}

// Get retrieves the blobs by keys and satisfies the Blob interface.
func (f *fileSystem) Get(keys []string) (map[string][]byte, error) {
	f.RLock()
	defer f.RUnlock()

	blobs := make(map[string][]byte, len(keys))
	for _, key := range keys {
		b, err := ioutil.ReadFile(filepath.Join(f.root, key))
		if err != nil {
			if os.IsNotExist(err) {
				return nil, store.ErrNotFound
			}
			return nil, err
		}
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// File does not exist. This is ok.
				continue
			}
			return nil, fmt.Errorf("get %v: %v", key, err)
		}
		blobs[key] = b
	}

	return blobs, nil
}

// Put is a stub to satisfy the Blob interface.
func (f *fileSystem) Put(blobs [][]byte) ([]string, error) {
	return []string{}, nil
}

// Del is a stub to satisfy the Blob interface.
func (f *fileSystem) Del(keys []string) error {
	return nil
}

// Enum is a stub to satisfy the Blob interface.
func (f *fileSystem) Enum(cb func(key string, blob []byte) error) error {
	return nil
}

// Close is a stub to satisfy the Blob interface.
func (f *fileSystem) Close() {}
