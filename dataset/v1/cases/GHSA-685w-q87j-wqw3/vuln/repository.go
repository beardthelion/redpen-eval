// Source: https://github.com/distribution/distribution
// Ref: 39d5bf77773818e2e38e0bd87f8ff75d4be740f1 Path: internal/client/repository.go
// Excerpted and modified from https://github.com/distribution/distribution@39d5bf77773818e2e38e0bd87f8ff75d4be740f1 on 2026-10-20
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
	m, _, err := distribution.UnmarshalManifest(mt, body)
	if err != nil {
		return nil, err
	}
	return m, nil
}
