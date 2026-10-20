// Source: https://github.com/gomarkdown/markdown
// Ref: 61af6e1e69710c5ca13cfbaaaa1bc11bc763a8a9 Path: parser/parser.go
// Excerpted and modified from https://github.com/gomarkdown/markdown@61af6e1e69710c5ca13cfbaaaa1bc11bc763a8a9 on 2026-10-20
// License: BSD-2-Clause, see licenses/gomarkdown__markdown/LICENSE.txt
// Copyright © 2011 Russ Ross
func IsSafeURL(url []byte) bool {
	nLink := len(url)
	for _, path := range Paths {
		nPath := len(path)
		// Length must be checked before slicing; short urls (empty, ".", "..")
		// are shorter than some path prefixes and would panic on url[:nPath].
		// See GHSA-cv23-7vc5-jfh7.
		if nLink < nPath {
			continue
		}
		if bytes.Equal(url[:nPath], path) {
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
