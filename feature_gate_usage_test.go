package auth

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoLegacySelfRegistrationKey(t *testing.T) {
	key := "users." + "self_registration"

	root, err := os.Getwd()
	require.NoError(t, err)

	var matches []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(key)) {
			matches = append(matches, path)
		}
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, matches)
}
