package pkgcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// errNotFound means the object isn't in the cache. Any other error from a
// store is a fault, and the transform fails open on it.
var errNotFound = errors.New("pkgcache: object not in cache")

// object is a cached package file, ready to stream to a client.
type object struct {
	Body        io.ReadCloser
	Size        int64
	ContentType string // "" means application/octet-stream
}

// store is where cached package files live. The transform only ever gets
// and puts whole objects: it never lists, overwrites on purpose or deletes.
// Expiry is the store's own business (an S3 lifecycle rule, a cron job).
type store interface {
	// Get returns the object, or errNotFound when the key isn't cached.
	Get(ctx context.Context, key string) (*object, error)
	// Put stores exactly size bytes read from body under key. When body
	// returns an error before size bytes, Put must fail and leave nothing
	// behind: a half-written package must never be served.
	Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error
}

// ---------------------------------------------------------------------------
// S3 (or an S3-compatible service)

// s3Store keeps cached files in one bucket.
//
// IAM: the proxy's role needs s3:GetObject and s3:PutObject on the bucket's
// objects, and s3:ListBucket on the bucket itself. Without ListBucket, S3
// answers a missing key with 403 instead of 404, which the transform can't
// tell apart from a real permission problem.
type s3Store struct {
	client *s3.Client
	bucket string
}

type s3Settings struct {
	Bucket       string
	Region       string // "" = the default chain's region
	Endpoint     string // "" = AWS; set for MinIO, R2 and other S3-compatible services
	UsePathStyle bool   // bucket in the path, not the host name (most S3-compatible services)
}

func newS3Store(ctx context.Context, s s3Settings) (*s3Store, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if s.Region != "" {
		opts = append(opts, awsconfig.WithRegion(s.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("pkgcache: loading AWS config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if s.Endpoint != "" {
			o.BaseEndpoint = aws.String(s.Endpoint)
		}
		o.UsePathStyle = s.UsePathStyle
	})
	return &s3Store{client: client, bucket: s.Bucket}, nil
}

func (s *s3Store) Get(ctx context.Context, key string) (*object, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, errNotFound
		}
		return nil, fmt.Errorf("pkgcache: s3 get s3://%s/%s: %w", s.bucket, key, err)
	}
	size := int64(-1)
	if out.ContentLength != nil {
		size = *out.ContentLength
	}
	return &object{Body: out.Body, Size: size, ContentType: aws.ToString(out.ContentType)}, nil
}

// Put uses a single PutObject with the exact Content-Length. A single PUT is
// atomic: S3 creates the object only when every byte arrived, so an upload
// cut off part way leaves nothing behind (no multipart parts to clean up).
// One PUT holds up to 5 GiB, far above any package file.
func (s *s3Store) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("pkgcache: s3 put s3://%s/%s: %w", s.bucket, key, err)
	}
	return nil
}

func isS3NotFound(err error) bool {
	var noSuchKey *s3types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return true
	}
	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return true
	}
	var httpErr interface{ HTTPStatusCode() int }
	return errors.As(err, &httpErr) && httpErr.HTTPStatusCode() == http.StatusNotFound
}

// ---------------------------------------------------------------------------
// A local directory

// dirStore keeps cached files under a directory, one file per key. Content
// types aren't kept; package files are served as application/octet-stream.
//
// Nothing here expires files. Age them out from outside, for example with
// `find <dir> -type f -mtime +90 -delete` from cron. Temporary files from an
// interrupted write are named .pkgcache-tmp-* and are safe to delete.
type dirStore struct {
	root string
}

func newDirStore(dir string) (*dirStore, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("pkgcache: directory %q: %w", dir, err)
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("pkgcache: creating directory %s: %w", root, err)
	}
	return &dirStore{root: root}, nil
}

// pathFor maps a key to a file under root, refusing anything that would
// land outside it.
func (d *dirStore) pathFor(key string) (string, error) {
	p := filepath.Join(d.root, filepath.FromSlash(key))
	if !strings.HasPrefix(p, d.root+string(filepath.Separator)) {
		return "", fmt.Errorf("pkgcache: key %q is outside the cache directory", key)
	}
	return p, nil
}

func (d *dirStore) Get(_ context.Context, key string) (*object, error) {
	p, err := d.pathFor(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pkgcache: opening %s: %w", p, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("pkgcache: stat %s: %w", p, err)
	}
	return &object{Body: f, Size: info.Size()}, nil
}

// Put writes to a temporary file in the same directory and renames it into
// place only when every byte arrived. A rename within one directory is
// atomic, so readers see the whole file or nothing.
func (d *dirStore) Put(ctx context.Context, key string, body io.Reader, size int64, _ string) error {
	p, err := d.pathFor(key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("pkgcache: creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".pkgcache-tmp-*")
	if err != nil {
		return fmt.Errorf("pkgcache: creating a temporary file in %s: %w", dir, err)
	}
	written, err := io.Copy(tmp, body)
	if err == nil && written != size {
		err = fmt.Errorf("pkgcache: got %d bytes, expected %d", written, size)
	}
	if err == nil {
		err = ctx.Err()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("pkgcache: writing %s: %w", p, err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("pkgcache: renaming into %s: %w", p, err)
	}
	return nil
}
