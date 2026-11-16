// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package forwarding

import (
	"bufio"
	"bytes"
	"net/http"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
)

func Test_ForwardedRequest_GenerateParse(t *testing.T) {
	testForwardedRequestGenerateParse(t)
}

func Benchmark_ForwardedRequest_GenerateParse(b *testing.B) {
	var totalSize int64
	var numRuns int64
	for b.Loop() {
		totalSize += testForwardedRequestGenerateParse(b)
		numRuns++
	}
	b.Logf("message size per op: %d", totalSize/numRuns)
}

func testForwardedRequestGenerateParse(t testing.TB) int64 {
	bodBuf := bytes.NewReader([]byte(`{ "foo": "bar", "zip": { "argle": "bargle", neet: 0 } }`))
	req, err := http.NewRequest("FOOBAR", "https://pushit.real.good:9281/snicketysnack?furbleburble=bloopetybloop", bodBuf)
	if err != nil {
		t.Fatal(err)
	}

	// We want to get the fields we would expect from an incoming request, so
	// we write it out and then read it again
	buf1 := bytes.NewBuffer(nil)
	err = req.Write(buf1)
	if err != nil {
		t.Fatal(err)
	}

	// Read it back in, parsing like a server
	bufr1 := bufio.NewReader(buf1)
	initialReq, err := http.ReadRequest(bufr1)
	if err != nil {
		t.Fatal(err)
	}

	// Generate the request with the forwarded request in the body
	forwardedRequest, err := GenerateForwardedRequest(initialReq)
	if err != nil {
		t.Fatal(err)
	}

	size := int64(proto.Size(forwardedRequest))

	// Now extract the forwarded request to generate a final request for processing
	finalReq, err := ParseForwardedRequest(forwardedRequest)
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case initialReq.Method != finalReq.Method:
		t.Fatalf("bad method:\ninitialReq:\n%#v\nfinalReq:\n%#v\n", *initialReq, *finalReq)
	case initialReq.RemoteAddr != finalReq.RemoteAddr:
		t.Fatalf("bad remoteaddr:\ninitialReq:\n%#v\nfinalReq:\n%#v\n", *initialReq, *finalReq)
	case initialReq.Host != finalReq.Host:
		t.Fatalf("bad host:\ninitialReq:\n%#v\nfinalReq:\n%#v\n", *initialReq, *finalReq)
	case !reflect.DeepEqual(initialReq.URL, finalReq.URL):
		t.Fatalf("bad url:\ninitialReq:\n%#v\nfinalReq:\n%#v\n", *initialReq.URL, *finalReq.URL)
	case !reflect.DeepEqual(initialReq.Header, finalReq.Header):
		t.Fatalf("bad header:\ninitialReq:\n%#v\nfinalReq:\n%#v\n", *initialReq, *finalReq)
	default:
		// Compare bodies
		bodBuf.Seek(0, 0)
		initBuf := bytes.NewBuffer(nil)
		_, err = initBuf.ReadFrom(bodBuf)
		if err != nil {
			t.Fatal(err)
		}
		finBuf := bytes.NewBuffer(nil)
		_, err = finBuf.ReadFrom(finalReq.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(initBuf.Bytes(), finBuf.Bytes()) {
			t.Fatalf("badbody :\ninitialReq:\n%#v\nfinalReq:\n%#v\n", initBuf.Bytes(), finBuf.Bytes())
		}
	}

	return size
}
