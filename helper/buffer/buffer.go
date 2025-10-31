package buffer

import (
	"bytes"
	"io"
)

// nopSeekableReader implements ReadSeekCloser by forwarding read and seek to
// the underlying ReaderSeeker and implementing Close as a noop. Due to
// net/http.Request.Body contracts, we need to add close support while
// preserving Seek capability.
type nopSeekableReader struct {
	io.ReadSeeker
}

func (n nopSeekableReader) Close() error { return nil }

func NewSeekableReader(orig io.Reader) (io.ReadSeekCloser, error) {
	if seekReaderCloser, ok := orig.(io.ReadSeekCloser); ok {
		return seekReaderCloser, nil
	}

	if seekReader, ok := orig.(io.ReadSeeker); ok {
		return nopSeekableReader{seekReader}, nil
	}

	data, err := io.ReadAll(orig)
	if err != nil {
		return nil, err
	}

	if closer, ok := orig.(io.Closer); ok {
		err = closer.Close()
		if err != nil {
			return nil, err
		}
	}

	return &nopSeekableReader{
		bytes.NewReader(data),
	}, nil
}
