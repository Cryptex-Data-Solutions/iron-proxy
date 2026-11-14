package pkgcache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirStore_PutThenGet(t *testing.T) {
	st, err := newDirStore(t.TempDir())
	require.NoError(t, err)
	key := "npm/registry.npmjs.org/@babel/core/-/core-7.26.0.tgz"

	_, err = st.Get(context.Background(), key)
	require.ErrorIs(t, err, errNotFound)

	require.NoError(t, st.Put(context.Background(), key, bytes.NewReader([]byte("tarball")), 7, "application/octet-stream"))

	obj, err := st.Get(context.Background(), key)
	require.NoError(t, err)
	defer obj.Body.Close()
	require.Equal(t, int64(7), obj.Size)
	data, err := io.ReadAll(obj.Body)
	require.NoError(t, err)
	require.Equal(t, "tarball", string(data))
}

func TestDirStore_IncompleteWriteLeavesNothing(t *testing.T) {
	root := t.TempDir()
	st, err := newDirStore(root)
	require.NoError(t, err)
	key := "nuget/api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg"

	// Fewer bytes than promised.
	require.Error(t, st.Put(context.Background(), key, bytes.NewReader([]byte("abc")), 10, ""))
	// The reader fails part way.
	failing := io.MultiReader(bytes.NewReader([]byte("abc")), &errReader{errors.New("connection reset")})
	require.Error(t, st.Put(context.Background(), key, failing, 10, ""))

	_, err = st.Get(context.Background(), key)
	require.ErrorIs(t, err, errNotFound)

	// No temporary files left behind.
	var leftovers []string
	require.NoError(t, filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			leftovers = append(leftovers, p)
		}
		return err
	}))
	require.Empty(t, leftovers)
}

func TestDirStore_RefusesKeysOutsideTheDirectory(t *testing.T) {
	st, err := newDirStore(t.TempDir())
	require.NoError(t, err)

	err = st.Put(context.Background(), "../escape", bytes.NewReader([]byte("x")), 1, "")
	require.ErrorContains(t, err, "outside the cache directory")
	_, err = st.Get(context.Background(), "../escape")
	require.ErrorContains(t, err, "outside the cache directory")
}

func TestNewStore_ExactlyOneKind(t *testing.T) {
	_, err := newStore(config{})
	require.ErrorContains(t, err, "set bucket (S3) or directory")

	_, err = newStore(config{Bucket: "b", Directory: t.TempDir()})
	require.ErrorContains(t, err, "not both")

	_, err = newStore(config{Directory: t.TempDir(), Endpoint: "http://minio:9000"})
	require.ErrorContains(t, err, "only apply to a bucket")

	st, err := newStore(config{Directory: t.TempDir()})
	require.NoError(t, err)
	require.IsType(t, &dirStore{}, st)
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }
