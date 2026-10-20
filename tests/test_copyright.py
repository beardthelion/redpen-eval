import pytest

from redpen.dataset import _copyright

MUST_MATCH = [
    ("Copyright (c) 2017-2018 the project authors.", "Copyright (c) 2017-2018 the project authors."),
    ("// Copyright 2021 The KEDA Authors", "Copyright 2021 The KEDA Authors"),
    ("Copyright © 2011 Russ Ross", "Copyright © 2011 Russ Ross"),
    ("# Copyright (C) 2014-2026 Tom Wallroth", "Copyright (C) 2014-2026 Tom Wallroth"),
    (" * Copyright 2019 The Vitess Authors.", "Copyright 2019 The Vitess Authors."),
    ("   Copyright The containerd Authors.", "Copyright The containerd Authors."),
    ("/* COPYRIGHT (c) 2020 Foo Inc. */", "COPYRIGHT (c) 2020 Foo Inc."),
    ("-- copyright 2015 Lua Person", "copyright 2015 Lua Person"),
    ("Copyright (c) 2020 Jane Doe <jane@example.com>", "Copyright (c) 2020 Jane Doe <jane@example.com>"),
]

MUST_NOT_MATCH = [
    '"Licensor" shall mean the copyright owner or entity authorized by',
    "copyright notice, this list of conditions",
    "Copyright [yyyy] [name of copyright owner]",
    "Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>",
    "the copyright holders",
    "   Copyright Notice",
    "// Copyright holders may not be liable",
    "    Copyright (C) <year>  <name of author>",
    "    <program>  Copyright (C) <year>  <name of author>",
    "Copyright (c) [year] [fullname]",
]


@pytest.mark.parametrize("line,expected", MUST_MATCH)
def test_real_notice_in_sink_matches(line, expected):
    assert _copyright(f"package x\n{line}\nfunc f() {{}}\n", [], "o", "r") == (expected, "sink_file")


@pytest.mark.parametrize("line,expected", MUST_MATCH)
def test_real_notice_in_license_matches(line, expected):
    assert _copyright("package x\n", [f"Some License\n{line}\n"], "o", "r") == (expected, "license_file")


@pytest.mark.parametrize("line", MUST_NOT_MATCH)
def test_non_notice_rejected(line):
    assert _copyright(f"// {line}\n", [f"{line}\n"], "o", "r") == ("Copyright the o/r contributors", "fallback")


APACHE_LIKE = """
                                 Apache License
                           Version 2.0, January 2004

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      2. Grant of Copyright License. Subject to the terms and conditions of

   APPENDIX: How to apply the Apache License to your work.

      Copyright [yyyy] [name of copyright owner]
"""

AGPL_LIKE = """                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
  The precise terms and conditions for copying, distribution and
modification follow. "Copyright" also means copyright-like laws that apply

    Copyright (C) <year>  <name of author>
"""


def test_apache_without_real_notice_falls_back():
    assert _copyright("package x\n", [APACHE_LIKE], "kedacore", "keda") == (
        "Copyright the kedacore/keda contributors", "fallback")


def test_agpl_with_only_fsf_line_falls_back():
    assert _copyright("package x\n", [AGPL_LIKE], "0xJacky", "nginx-ui") == (
        "Copyright the 0xJacky/nginx-ui contributors", "fallback")


def test_real_notice_after_template_in_license_found():
    lic = APACHE_LIKE + "\n   Copyright 2019 The Real Authors\n"
    assert _copyright("package x\n", [lic], "o", "r") == ("Copyright 2019 The Real Authors", "license_file")


def test_sink_notice_beats_license_notice():
    sink = "// Copyright 2021 The KEDA Authors\npackage x\n"
    lic = "MIT License\n\nCopyright (c) 2023 Someone Else\n"
    assert _copyright(sink, [lic], "o", "r") == ("Copyright 2021 The KEDA Authors", "sink_file")
