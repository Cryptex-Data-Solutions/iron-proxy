package transform

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBufferedBody_Read(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestBufferedBody_ResetAndReread(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))

	body.Reset()

	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestBufferedBody_MultipleResets(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("abc")), 1024)

	for i := 0; i < 5; i++ {
		data, err := io.ReadAll(body)
		require.NoError(t, err)
		require.Equal(t, "abc", string(data))
		body.Reset()
	}
}

func TestBufferedBody_MaxBytesTruncates(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello world")), 5)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))

	// Reset and re-read: same truncated data.
	body.Reset()
	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestBufferedBody_Truncated(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		maxBytes int64
		read     bool
		wantData string
		want     bool
	}{
		{name: "not read yet", body: "hello world", maxBytes: 5, read: false, want: false},
		{name: "shorter than the limit", body: "hey", maxBytes: 5, read: true, wantData: "hey", want: false},
		{name: "exactly the limit", body: "hello", maxBytes: 5, read: true, wantData: "hello", want: false},
		{name: "one byte over the limit", body: "hello!", maxBytes: 5, read: true, wantData: "hello", want: true},
		{name: "unlimited", body: "hello world", maxBytes: 0, read: true, wantData: "hello world", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := NewBufferedBody(io.NopCloser(strings.NewReader(tt.body)), tt.maxBytes)
			if tt.read {
				data, err := io.ReadAll(body)
				require.NoError(t, err)
				require.Equal(t, tt.wantData, string(data))
			}
			require.Equal(t, tt.want, body.Truncated())
		})
	}
}

func TestBufferedBody_MarkTruncated(t *testing.T) {
	// A rewrite of a truncated body keeps the flag, even if it is longer.
	replacement := NewBufferedBodyFromBytes([]byte("a longer rewritten body"))
	require.False(t, replacement.Truncated())
	replacement.MarkTruncated()
	require.True(t, replacement.Truncated())
}

func TestBufferedBody_Unlimited(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello world")), 0)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))
}

func TestBufferedBody_NilBody(t *testing.T) {
	body := NewBufferedBody(nil, 1024)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestBufferedBody_Close(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)
	require.NoError(t, body.Close())

	// After consuming, close is a no-op.
	body2 := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)
	_, _ = io.ReadAll(body2)
	require.NoError(t, body2.Close())
}

func TestBufferedBody_StreamingReader_Unbuffered(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("stream me")), 1024)

	// StreamingReader without any prior Read should return the original.
	reader := body.StreamingReader()
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "stream me", string(data))
}

func TestBufferedBody_StreamingReader_Buffered(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("buffered")), 1024)

	// Read first to trigger buffering.
	_, _ = io.ReadAll(body)
	body.Reset()

	reader := body.StreamingReader()
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "buffered", string(data))
}

func TestBufferedBody_Len(t *testing.T) {
	body := NewBufferedBody(io.NopCloser(strings.NewReader("hello")), 1024)

	// Before any read, Len is unknown.
	require.Equal(t, -1, body.Len())

	// After reading, Len returns the buffered size.
	_, _ = io.ReadAll(body)
	require.Equal(t, 5, body.Len())
}

func TestBufferedBodyFromBytes(t *testing.T) {
	body := NewBufferedBodyFromBytes([]byte("pre-buffered"))

	require.Equal(t, 12, body.Len())

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "pre-buffered", string(data))

	body.Reset()
	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "pre-buffered", string(data))
}
