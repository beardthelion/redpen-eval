// Source: https://github.com/distribution/distribution
// Ref: 8f91c26c8888a95a36c2357a6e30bc15d4dd76d3 Path: internal/client/repository.go
// Excerpted and modified from https://github.com/distribution/distribution@8f91c26c8888a95a36c2357a6e30bc15d4dd76d3 on 2026-10-20
// License: Apache-2.0, see licenses/distribution__distribution/LICENSE
// Copyright the distribution/distribution contributors
func (ms *manifests) Get(ctx context.Context, dgst digest.Digest, options ...distribution.ManifestServiceOption) (distribution.Manifest, error) {
	var (
		digestOrTag string
		ref         reference.Named
		err         error
		contentDgst *digest.Digest
		mediaTypes  []string
	)

	for _, option := range options {
		switch opt := option.(type) {
		case distribution.WithTagOption:
			digestOrTag = opt.Tag
			ref, err = reference.WithTag(ms.name, opt.Tag)
			if err != nil {
				return nil, err
			}
		case contentDigestOption:
			contentDgst = opt.digest
		case distribution.WithManifestMediaTypesOption:
			mediaTypes = opt.MediaTypes
		default:
			err := option.Apply(ms)
			if err != nil {
				return nil, err
			}
		}
	}

	// byDigest records whether the caller pinned the manifest by digest (as
	// opposed to fetching by tag). When true, the returned content must hash to
	// the requested digest.
	byDigest := digestOrTag == ""
	if digestOrTag == "" {
		digestOrTag = dgst.String()
		ref, err = reference.WithDigest(ms.name, dgst)
		if err != nil {
			return nil, err
		}
	}

	if len(mediaTypes) == 0 {
		mediaTypes = distribution.ManifestMediaTypes()
	}

	u, err := ms.ub.BuildManifestURL(ref)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	for _, t := range mediaTypes {
		req.Header.Add("Accept", t)
	}

	if _, ok := ms.etags[digestOrTag]; ok {
		req.Header.Set("If-None-Match", ms.etags[digestOrTag])
	}

	resp, err := ms.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, distribution.ErrManifestNotModified
	}
	if err := HandleHTTPResponseError(resp); err != nil {
		return nil, err
	}

	if contentDgst != nil {
		dgst, err := digest.Parse(resp.Header.Get("Docker-Content-Digest"))
		if err == nil {
			*contentDgst = dgst
		}
	}
	mt := resp.Header.Get("Content-Type")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// When the manifest was requested by digest, verify that the content the
	// registry returned actually hashes to that digest. The server-supplied
	// Docker-Content-Digest header is not trustworthy: a malicious registry or
	// a MITM can forge it while serving arbitrary bytes. Without this check,
	// digest pinning provides no integrity guarantee.
	if byDigest {
		// Reject a digest whose algorithm is unsupported/unavailable rather
		// than letting dgst.Verifier() panic; such a digest cannot be verified,
		// so fail closed.
		if err := dgst.Validate(); err != nil {
			return nil, err
		}
		verifier := dgst.Verifier()
		if _, err := verifier.Write(body); err != nil {
			return nil, err
		}
		if !verifier.Verified() {
			return nil, fmt.Errorf("manifest digest mismatch: requested %s but received content does not match", dgst)
		}
	}

	m, _, err := distribution.UnmarshalManifest(mt, body)
	if err != nil {
		return nil, err
	}
	return m, nil
}
