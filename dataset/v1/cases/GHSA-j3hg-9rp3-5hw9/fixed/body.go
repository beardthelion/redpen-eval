// Source: https://github.com/0xJacky/nginx-ui
// Ref: 8c9b9a1aff218ee6c980d047b750e49da3c46796 Path: internal/nodeauth/body.go
// Excerpted and modified from https://github.com/0xJacky/nginx-ui@8c9b9a1aff218ee6c980d047b750e49da3c46796 on 2026-10-20
// License: AGPL-3.0, see licenses/0xJacky__nginx-ui/LICENSE
// Copyright the 0xJacky/nginx-ui contributors
// This excerpt is released under the GNU Affero General Public License v3.0.

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
)

// Keep signed node traffic within the bundled reverse proxy's upload limit,
// including deployments that expose the application server directly.
const maxStagedRequestBodySize int64 = 128 << 20

var errRequestBodyTooLarge = errors.New("node request body is too large")

type temporaryRequestBody struct {
	*os.File
	path string
}
// ... lines 24-35 omitted ...

func stageRequestBody(request *http.Request) (string, error) {
	return stageRequestBodyWithLimit(request, maxStagedRequestBodySize)
}

func stageRequestBodyWithLimit(request *http.Request, limit int64) (string, error) {
	digest := sha256.New()
	if request.Body == nil || request.Body == http.NoBody {
		return formatContentDigest(digest), nil
	}
	if request.ContentLength > limit {
		_ = request.Body.Close()
		return "", requestBodyTooLargeError(limit)
	}

	temporary, err := os.CreateTemp("", "nginx-ui-node-request-body-*")
	if err != nil {
		return "", fmt.Errorf("stage signed request body: %w", err)
	}
	path := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(path)
	}

	size, err := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(request.Body, limit))
	if err == nil {
		var extra int64
		extra, err = io.CopyN(io.Discard, request.Body, 1)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if extra > 0 {
			cleanup()
			_ = request.Body.Close()
			return "", requestBodyTooLargeError(limit)
		}
	}
	closeErr := request.Body.Close()
	if err != nil {
		cleanup()
		return "", fmt.Errorf("stage signed request body: %w", err)
	}
	if closeErr != nil {
		cleanup()
		return "", fmt.Errorf("close original signed request body: %w", closeErr)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync signed request body: %w", err)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return "", fmt.Errorf("rewind signed request body: %w", err)
	}

	request.Body = &temporaryRequestBody{File: temporary, path: path}
	request.ContentLength = size
	return formatContentDigest(digest), nil
}

func requestBodyTooLargeError(limit int64) error {
	return fmt.Errorf("%w: limit is %d bytes", errRequestBodyTooLarge, limit)
}

func formatContentDigest(digest hash.Hash) string {
	return "sha-256=:" + base64.StdEncoding.EncodeToString(digest.Sum(nil)) + ":"
}
