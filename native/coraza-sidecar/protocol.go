package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire framing
//
// Every message in both directions is a 4-byte big-endian length followed by
// that many payload bytes. The first payload byte selects the encoding:
//
//	'{'    legacy JSON envelope (unchanged, still accepted)
//	0xC2   binary v1 request or response
//	0xC1   handshake (capability negotiation)
//
// 0xC1/0xC2 are not valid JSON starts, so the discriminator is unambiguous and
// a legacy peer (which only understands JSON) simply fails to decode a
// handshake frame and answers with a 400 JSON block. The client treats that as
// "this server is JSON only" and keeps using the JSON path on that connection.
const (
	frameMagicJSON      = '{'
	frameMagicHandshake = 0xC1
	frameMagicBinary    = 0xC2

	wireVersion = 1

	// binaryRequestHeaderLen is the fixed request header:
	//   magic, version, flags, reserved,
	//   method_len, uri_len, proto_len, header_count,
	//   body_len, body_size, original_size, header_blob_len
	binaryRequestHeaderLen = 28

	// binaryResponseHeaderLen is:
	//   magic, version, decision, flags, status, reason_len
	binaryResponseHeaderLen = 8

	flagHasBody   = 1 << 0
	flagTruncated = 1 << 1

	decisionAllow = 0
	decisionBlock = 1
)

var (
	errFrameTooShort   = errors.New("binary frame is shorter than its header")
	errFrameVersion    = errors.New("unsupported binary frame version")
	errFrameLayout     = errors.New("binary frame length does not match its header")
	errFrameHeaders    = errors.New("binary header block does not match header count")
	errFrameBodyFlag   = errors.New("binary frame body flag does not match body length")
	errResponseShort   = errors.New("binary response frame is too short")
	errResponseLayout  = errors.New("binary response frame length does not match its header")
	errResponseUnknown = errors.New("binary response carries an unknown decision")
)

// wireRequest is the decoded request envelope, independent of wire encoding.
// Body may alias the frame buffer; callers must not retain it past the current
// evaluation.
type wireRequest struct {
	Method       string
	URI          string
	HTTPVersion  string
	Headers      [][2]string
	Body         []byte
	HasBody      bool
	BodySize     int
	OriginalSize int
	Truncated    bool
}

// frameReader reads length-prefixed frames, reusing one buffer per connection
// so steady-state requests do not allocate. Oversized (up to maxFrame) frames
// use a temporary buffer instead of growing the retained one.
type frameReader struct {
	r   io.Reader
	buf []byte
}

const retainFrameBuffer = 1 << 20

func (fr *frameReader) next() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n > maxFrame {
		return nil, fmt.Errorf("frame of %d bytes exceeds %d byte limit", n, maxFrame)
	}
	if n > retainFrameBuffer {
		buf := make([]byte, n)
		if _, err := io.ReadFull(fr.r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	if cap(fr.buf) < n {
		fr.buf = make([]byte, n)
	}
	frame := fr.buf[:n]
	if _, err := io.ReadFull(fr.r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// decodeBinaryRequest parses a binary v1 request without copying the body.
// Every length is validated before use, so a malformed frame can only produce
// an error, never an out-of-range slice.
func decodeBinaryRequest(payload []byte) (*wireRequest, error) {
	if len(payload) < binaryRequestHeaderLen {
		return nil, errFrameTooShort
	}
	if payload[0] != frameMagicBinary {
		return nil, errFrameTooShort
	}
	if payload[1] != wireVersion {
		return nil, fmt.Errorf("%w: %d", errFrameVersion, payload[1])
	}
	flags := payload[2]
	methodLen := int(binary.BigEndian.Uint16(payload[4:6]))
	uriLen := int(binary.BigEndian.Uint16(payload[6:8]))
	protoLen := int(binary.BigEndian.Uint16(payload[8:10]))
	headerCount := int(binary.BigEndian.Uint16(payload[10:12]))
	bodyLen := int(binary.BigEndian.Uint32(payload[12:16]))
	bodySize := int(binary.BigEndian.Uint32(payload[16:20]))
	originalSize := int(binary.BigEndian.Uint32(payload[20:24]))
	blobLen := int(binary.BigEndian.Uint32(payload[24:28]))

	if bodyLen < 0 || blobLen < 0 || bodySize < 0 || originalSize < 0 {
		return nil, errFrameLayout
	}
	stringsLen := methodLen + uriLen + protoLen
	// bodyLen/blobLen come from uint32s, so this cannot overflow int on 64-bit
	// and the comparison below is exact.
	if binaryRequestHeaderLen+stringsLen+blobLen+bodyLen != len(payload) {
		return nil, errFrameLayout
	}

	off := binaryRequestHeaderLen
	req := &wireRequest{
		Method:       string(payload[off : off+methodLen]),
		URI:          string(payload[off+methodLen : off+methodLen+uriLen]),
		HTTPVersion:  string(payload[off+methodLen+uriLen : off+stringsLen]),
		BodySize:     bodySize,
		OriginalSize: originalSize,
		Truncated:    flags&flagTruncated != 0,
	}
	off += stringsLen

	blob := payload[off : off+blobLen]
	off += blobLen
	headers := make([][2]string, 0, headerCount)
	for i := 0; i < headerCount; i++ {
		if len(blob) < 4 {
			return nil, errFrameHeaders
		}
		nameLen := int(binary.BigEndian.Uint16(blob[0:2]))
		valueLen := int(binary.BigEndian.Uint16(blob[2:4]))
		blob = blob[4:]
		if nameLen+valueLen > len(blob) {
			return nil, errFrameHeaders
		}
		headers = append(headers, [2]string{
			string(blob[:nameLen]),
			string(blob[nameLen : nameLen+valueLen]),
		})
		blob = blob[nameLen+valueLen:]
	}
	if len(blob) != 0 {
		return nil, errFrameHeaders
	}
	req.Headers = headers

	if flags&flagHasBody != 0 {
		if bodyLen == 0 {
			return nil, errFrameBodyFlag
		}
		req.HasBody = true
		req.Body = payload[off : off+bodyLen]
	} else if bodyLen != 0 {
		return nil, errFrameBodyFlag
	}
	return req, nil
}

// appendBinaryRequest encodes a request into dst (appending) in binary v1 form.
// It exists for tests and for the Rust-side parity fixtures.
func appendBinaryRequest(dst []byte, req *wireRequest) []byte {
	headerCount := len(req.Headers)
	blobLen := 0
	for _, h := range req.Headers {
		blobLen += 4 + len(h[0]) + len(h[1])
	}
	flags := byte(0)
	if req.HasBody {
		flags |= flagHasBody
	}
	if req.Truncated {
		flags |= flagTruncated
	}
	bodySize := req.BodySize
	if bodySize == 0 && req.HasBody {
		bodySize = len(req.Body)
	}
	start := len(dst)
	dst = append(dst, make([]byte, binaryRequestHeaderLen)...)
	hdr := dst[start:]
	hdr[0] = frameMagicBinary
	hdr[1] = wireVersion
	hdr[2] = flags
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(req.Method)))
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(req.URI)))
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(req.HTTPVersion)))
	binary.BigEndian.PutUint16(hdr[10:12], uint16(headerCount))
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(req.Body)))
	binary.BigEndian.PutUint32(hdr[16:20], uint32(bodySize))
	binary.BigEndian.PutUint32(hdr[20:24], uint32(req.OriginalSize))
	binary.BigEndian.PutUint32(hdr[24:28], uint32(blobLen))
	dst = append(dst, req.Method...)
	dst = append(dst, req.URI...)
	dst = append(dst, req.HTTPVersion...)
	for _, h := range req.Headers {
		var entry [4]byte
		binary.BigEndian.PutUint16(entry[0:2], uint16(len(h[0])))
		binary.BigEndian.PutUint16(entry[2:4], uint16(len(h[1])))
		dst = append(dst, entry[:]...)
		dst = append(dst, h[0]...)
		dst = append(dst, h[1]...)
	}
	dst = append(dst, req.Body...)
	return dst
}

// appendBinaryResponse encodes resp into dst (appending) in binary v1 form.
// The allow path writes only the fixed header.
func appendBinaryResponse(dst []byte, resp Response) []byte {
	decision := byte(decisionAllow)
	if resp.Decision == "block" {
		decision = decisionBlock
	}
	reason := resp.Reason
	if len(reason) > 0xFFFF {
		reason = reason[:0xFFFF]
	}
	var hdr [binaryResponseHeaderLen]byte
	hdr[0] = frameMagicBinary
	hdr[1] = wireVersion
	hdr[2] = decision
	binary.BigEndian.PutUint16(hdr[4:6], uint16(resp.Status))
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(reason)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, reason...)
	return dst
}

// decodeBinaryResponse parses a binary v1 response frame (without its length
// prefix). It is used by tests; the sidecar itself only encodes responses.
func decodeBinaryResponse(frame []byte) (Response, error) {
	if len(frame) < binaryResponseHeaderLen {
		return Response{}, errResponseShort
	}
	if frame[0] != frameMagicBinary || frame[1] != wireVersion {
		return Response{}, errResponseShort
	}
	status := int(binary.BigEndian.Uint16(frame[4:6]))
	reasonLen := int(binary.BigEndian.Uint16(frame[6:8]))
	if binaryResponseHeaderLen+reasonLen != len(frame) {
		return Response{}, errResponseLayout
	}
	resp := Response{Status: status, Reason: string(frame[binaryResponseHeaderLen:])}
	switch frame[2] {
	case decisionAllow:
		resp.Decision = "allow"
	case decisionBlock:
		resp.Decision = "block"
	default:
		return Response{}, errResponseUnknown
	}
	return resp, nil
}

func isHandshake(frame []byte) bool {
	return len(frame) >= 2 && frame[0] == frameMagicHandshake
}
