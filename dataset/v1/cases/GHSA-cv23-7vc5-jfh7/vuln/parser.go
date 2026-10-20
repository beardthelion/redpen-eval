// Source: https://github.com/gomarkdown/markdown
// Ref: e08cff860f76ff942dae8866ad88e4a3eca5ce8a Path: parser/parser.go
// Excerpted and modified from https://github.com/gomarkdown/markdown@e08cff860f76ff942dae8866ad88e4a3eca5ce8a on 2026-10-20
// License: BSD-2-Clause, see licenses/gomarkdown__markdown/LICENSE.txt
// Copyright © 2011 Russ Ross
func IsSafeURL(url []byte) bool {
	nLink := len(url)
	for _, path := range Paths {
		nPath := len(path)
		linkPrefix := url[:nPath]
		if nLink >= nPath && bytes.Equal(linkPrefix, path) {
			if nLink == nPath {
				return true
			} else if IsAlnum(url[nPath]) {
				return true
			}
		}
	}

	for _, prefix := range URIs {
		// TODO: handle unicode here
		// case-insensitive prefix test
		nPrefix := len(prefix)
		if nLink > nPrefix {
			linkPrefix := bytes.ToLower(url[:nPrefix])
			if bytes.Equal(linkPrefix, prefix) && IsAlnum(url[nPrefix]) {
				return true
			}
		}
	}

	return false
}
