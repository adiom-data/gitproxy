package gitproxy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/pktline"
)

const DefaultMaxPushHeaderBytes int64 = 1 << 20

// parseReceivePackRefs extracts refs from the command list at the start of a
// git-receive-pack request body.
func parseReceivePackRefs(body []byte) ([]Ref, error) {
	var refs []Ref
	if bytes.Equal(body, pktline.FlushPkt) {
		return refs, nil
	}

	scanner := pktline.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			break
		}

		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, []byte("shallow ")) {
			if err := validateHashString(string(bytes.TrimPrefix(line, []byte("shallow ")))); err != nil {
				return nil, fmt.Errorf("invalid shallow line: %w", err)
			}
			continue
		}

		ref, err := parseReceivePackCommand(line)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return refs, nil
}

func parseReceivePackCommand(line []byte) (Ref, error) {
	command, _, _ := bytes.Cut(line, []byte{0})
	parts := bytes.SplitN(command, []byte(" "), 3)
	if len(parts) != 3 {
		return Ref{}, fmt.Errorf("malformed command")
	}

	oldSHA := string(parts[0])
	newSHA := string(parts[1])
	refName := strings.TrimSpace(string(parts[2]))
	if err := validateHashString(oldSHA); err != nil {
		return Ref{}, fmt.Errorf("invalid old sha: %w", err)
	}
	if err := validateHashString(newSHA); err != nil {
		return Ref{}, fmt.Errorf("invalid new sha: %w", err)
	}
	if refName == "" {
		return Ref{}, fmt.Errorf("missing ref name")
	}

	ref := parseRef(refName)
	ref.OldSHA = oldSHA
	ref.NewSHA = newSHA
	ref.Action = refAction(oldSHA, newSHA)
	return ref, nil
}

func validateHashString(value string) error {
	if len(value) != 40 {
		return fmt.Errorf("expected 40 hex characters, got %d", len(value))
	}
	_, err := hex.DecodeString(value)
	return err
}

func refAction(oldSHA, newSHA string) RefAction {
	const zeroHash = "0000000000000000000000000000000000000000"
	switch {
	case oldSHA == zeroHash && newSHA == zeroHash:
		return RefActionUnknown
	case oldSHA == zeroHash:
		return RefActionCreate
	case newSHA == zeroHash:
		return RefActionDelete
	default:
		return RefActionUpdate
	}
}

func readReceivePackHeader(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPushHeaderBytes
	}

	var header bytes.Buffer
	for {
		var sizeHeader [4]byte
		if _, err := io.ReadFull(r, sizeHeader[:]); err != nil {
			return nil, err
		}
		if err := writeBounded(&header, sizeHeader[:], maxBytes); err != nil {
			return nil, err
		}
		if bytes.Equal(sizeHeader[:], pktline.FlushPkt) {
			return header.Bytes(), nil
		}

		size, err := strconv.ParseInt(string(sizeHeader[:]), 16, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid pkt-line length: %w", err)
		}
		if size < 4 || size > pktline.OversizePayloadMax+4 {
			return nil, fmt.Errorf("invalid pkt-line length: %d", size)
		}

		payload := make([]byte, size-4)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		if err := writeBounded(&header, payload, maxBytes); err != nil {
			return nil, err
		}
	}
}

func writeBounded(w *bytes.Buffer, data []byte, maxBytes int64) error {
	if int64(w.Len()+len(data)) > maxBytes {
		return fmt.Errorf("receive-pack header exceeds %d bytes", maxBytes)
	}
	_, err := w.Write(data)
	return err
}
