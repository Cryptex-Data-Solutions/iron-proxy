package pkgcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// uploadingBody is the response body on a cache miss. The client reads the
// registry's response through it as normal; every chunk it reads is also
// queued for upload to the store.
//
// The client always comes first. The upload never slows the client down:
// chunks are queued without blocking, and when the queue is full (the store
// is slower than the client) the upload is abandoned and the client carries
// on. Anything unusual abandons the upload the same way: a read error, a body
// shorter than Content-Length, a client that stops reading. An abandoned
// upload stores nothing, because Put fails when its reader errors.
//
// Why an idle timeout: the proxy copies the final response with io.Copy and
// never calls Close on it, so a client that disconnects mid-download is only
// visible as "no more reads". The feeder gives up after idleTimeout.
type uploadingBody struct {
	src      io.Reader // the registry's response
	srcClose func() error
	key      string
	size     int64 // Content-Length; the upload needs every byte of it
	read     int64 // bytes the client has read so far

	chunks      chan []byte  // chunks waiting for the feeder
	queuedBytes atomic.Int64 // bytes in chunks, not yet written to the pipe
	maxQueued   int64

	pipeWriter  *io.PipeWriter
	abort       chan struct{} // closed when the upload is abandoned
	abandoned   atomic.Bool
	abandonOnce sync.Once
	cancel      context.CancelFunc // cancels the store's Put
	finished    bool               // the client read every byte (EOF seen)

	logger *slog.Logger
}

// uploadSettings are the limits for one upload, from the transform's config.
type uploadSettings struct {
	maxQueuedBytes int64
	idleTimeout    time.Duration
	uploadTimeout  time.Duration
}

// startUpload begins uploading key while src streams to the client, and
// returns the body to give the client. release is called once when the
// upload has finished, whether it stored the object or not.
func startUpload(src io.ReadCloser, key string, size int64, contentType string, st store, settings uploadSettings, logger *slog.Logger, release func()) *uploadingBody {
	pipeReader, pipeWriter := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), settings.uploadTimeout)

	b := &uploadingBody{
		src:        src,
		srcClose:   src.Close,
		key:        key,
		size:       size,
		chunks:     make(chan []byte, 4096),
		maxQueued:  settings.maxQueuedBytes,
		pipeWriter: pipeWriter,
		abort:      make(chan struct{}),
		cancel:     cancel,
		logger:     logger,
	}

	// The uploader: one Put reading from the pipe.
	go func() {
		defer release()
		defer cancel()
		started := time.Now()
		err := st.Put(ctx, key, pipeReader, size, contentType)
		// Unblock the feeder if Put returned early (an S3 error).
		_ = pipeReader.CloseWithError(errors.New("pkgcache: upload finished"))
		if err != nil {
			if !b.abandoned.Load() {
				logger.Warn("pkgcache: upload failed, nothing stored",
					slog.String("key", key), slog.String("error", err.Error()))
			}
			return
		}
		logger.Info("pkgcache: stored",
			slog.String("key", key), slog.Int64("bytes", size),
			slog.Duration("took", time.Since(started)))
	}()

	// The feeder: moves queued chunks into the pipe, so the client's reads
	// never wait on the upload.
	go b.feed(settings.idleTimeout)

	return b
}

func (b *uploadingBody) feed(idleTimeout time.Duration) {
	idle := time.NewTimer(idleTimeout)
	defer idle.Stop()
	for {
		select {
		case <-b.abort:
			return
		case <-idle.C:
			b.abandonUpload("the client stopped reading for " + idleTimeout.String())
			return
		case chunk, ok := <-b.chunks:
			if !ok {
				// The client read every byte: finish the upload.
				_ = b.pipeWriter.Close()
				return
			}
			if _, err := b.pipeWriter.Write(chunk); err != nil {
				// The upload has already failed or been abandoned.
				b.abandonUpload("writing to the upload: " + err.Error())
				return
			}
			b.queuedBytes.Add(-int64(len(chunk)))
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(idleTimeout)
		}
	}
}

// abandonUpload stops the upload so nothing is stored. Safe to call more than
// once and from either goroutine. It never affects the client's stream.
func (b *uploadingBody) abandonUpload(reason string) {
	b.abandonOnce.Do(func() {
		b.abandoned.Store(true)
		close(b.abort)
		_ = b.pipeWriter.CloseWithError(fmt.Errorf("pkgcache: upload abandoned: %s", reason))
		b.cancel()
		b.logger.Info("pkgcache: upload abandoned, nothing stored",
			slog.String("key", b.key), slog.String("reason", reason))
	})
}

// Read gives the client the next bytes of the registry's response, and queues
// a copy for the upload.
func (b *uploadingBody) Read(p []byte) (int, error) {
	n, err := b.src.Read(p)
	if n > 0 {
		b.read += int64(n)
		b.queue(p[:n])
	}
	if err == io.EOF {
		if b.read == b.size {
			b.finish()
		} else {
			b.abandonUpload(fmt.Sprintf("the response had %d bytes, Content-Length said %d", b.read, b.size))
		}
	} else if err != nil {
		b.abandonUpload("reading the registry's response: " + err.Error())
	}
	return n, err
}

func (b *uploadingBody) queue(data []byte) {
	if b.abandoned.Load() || b.finished {
		return
	}
	if b.read > b.size {
		b.abandonUpload(fmt.Sprintf("the response is longer than Content-Length (%d bytes)", b.size))
		return
	}
	if b.queuedBytes.Load()+int64(len(data)) > b.maxQueued {
		b.abandonUpload(fmt.Sprintf("the store fell %d bytes behind the client", b.maxQueued))
		return
	}
	chunk := make([]byte, len(data)) // p is reused by the caller
	copy(chunk, data)
	b.queuedBytes.Add(int64(len(chunk)))
	select {
	case b.chunks <- chunk:
	default:
		b.abandonUpload("the upload queue is full")
	}
}

// finish tells the feeder the last chunk is queued. Called once, on EOF.
func (b *uploadingBody) finish() {
	if b.finished || b.abandoned.Load() {
		return
	}
	b.finished = true
	close(b.chunks)
}

// Close closes the registry's response. A close before every byte was read
// abandons the upload.
func (b *uploadingBody) Close() error {
	if !b.finished {
		b.abandonUpload("the response was closed before it was fully read")
	}
	return b.srcClose()
}
