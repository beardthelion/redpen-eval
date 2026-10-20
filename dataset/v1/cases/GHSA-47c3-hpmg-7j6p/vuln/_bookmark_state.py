# Source: https://github.com/posit-dev/py-shiny
# Ref: 48b4faa0d651476afa84d6423d57503b60716902 Path: shiny/bookmark/_bookmark_state.py
# Excerpted and modified from https://github.com/posit-dev/py-shiny@48b4faa0d651476afa84d6423d57503b60716902 on 2026-10-20
# License: MIT, see licenses/posit-dev__py-shiny/LICENSE
# Copyright (c) 2023 Posit Software, PBC
from __future__ import annotations

import os
from pathlib import Path

shiny_bookmarks_folder_name = "shiny_bookmarks"


def _local_dir(id: str) -> Path:
    # Try to save/load from current working directory as we do not know where the
    # app file is located
    return Path(os.getcwd()) / shiny_bookmarks_folder_name / id
