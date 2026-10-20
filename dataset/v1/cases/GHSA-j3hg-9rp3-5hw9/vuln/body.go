// Source: https://github.com/0xJacky/nginx-ui
// Ref: 1218a417ae9dfd3d053a7dce7d626ca9b8895361 Path: internal/nodeauth/body.go
// Excerpted and modified from https://github.com/0xJacky/nginx-ui@1218a417ae9dfd3d053a7dce7d626ca9b8895361 on 2026-10-20
// License: AGPL-3.0, see licenses/0xJacky__nginx-ui/LICENSE
// Copyright the 0xJacky/nginx-ui contributors
// This excerpt is released under the GNU Affero General Public License v3.0.

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
)

type temporaryRequestBody struct {
	*os.File
	path string
}
// ... lines 17-29 omitted ...
func stageRequestBody(request *http.Request) (string, error) {
	digest := sha256.New()
	if request.Body == nil || request.Body == http.NoBody {
		return formatContentDigest(digest), nil
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

	size, err := io.Copy(io.MultiWriter(temporary, digest), request.Body)
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

func formatContentDigest(digest hash.Hash) string {
	return "sha-256=:" + base64.StdEncoding.EncodeToString(digest.Sum(nil)) + ":"
}
