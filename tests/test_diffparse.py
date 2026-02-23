# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
from __future__ import annotations

import pytest

from pr_guardian.diffparse import (
    _parse_hunk_header,
    get_new_line_number,
    get_old_line_number,
    parse_diff,
    parse_patch,
)


def test_parse_diff_returns_empty_for_blank_input() -> None:
    diff = parse_diff("")

    assert diff.files == []


def test_parse_diff_supports_added_file() -> None:
    diff_text = """diff --git a/src/new.py b/src/new.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/new.py
@@ -0,0 +1,2 @@
+line1
+line2
"""

    diff = parse_diff(diff_text)

    assert len(diff.files) == 1
    file_diff = diff.files[0]
    assert file_diff.status == "added"
    assert len(file_diff.hunks) == 1
    assert file_diff.hunks[0].line_mappings == [(None, 1), (None, 2)]


def test_parse_diff_supports_removed_file() -> None:
    diff_text = """diff --git a/src/old.py b/src/old.py
deleted file mode 100644
index 1111111..0000000
--- a/src/old.py
+++ /dev/null
@@ -1,2 +0,0 @@
-line1
-line2
"""

    diff = parse_diff(diff_text)

    assert len(diff.files) == 1
    file_diff = diff.files[0]
    assert file_diff.status == "removed"
    assert file_diff.hunks[0].line_mappings == [(1, None), (2, None)]


def test_parse_patch_supports_multiple_hunks() -> None:
    patch = """@@ -1,3 +1,3 @@
 line1
-old2
+new2
 line3
@@ -10,2 +10,3 @@
 line10
+insert11
 line11
"""

    hunks = parse_patch(patch)

    assert len(hunks) == 2
    assert hunks[0].old_start == 1
    assert hunks[0].new_start == 1
    assert hunks[1].old_start == 10
    assert hunks[1].new_start == 10
    assert hunks[1].line_mappings == [(10, 10), (None, 11), (11, 12)]


def test_parse_diff_supports_rename_operation() -> None:
    diff_text = """diff --git a/src/old_name.py b/src/new_name.py
similarity index 100%
rename from src/old_name.py
rename to src/new_name.py
"""

    diff = parse_diff(diff_text)

    assert len(diff.files) == 1
    file_diff = diff.files[0]
    assert file_diff.status == "renamed"
    assert file_diff.old_path == "src/old_name.py"
    assert file_diff.new_path == "src/new_name.py"
    assert file_diff.hunks == []


def test_parse_patch_supports_no_newline_marker() -> None:
    patch = """@@ -1 +1 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
"""

    hunks = parse_patch(patch)

    assert len(hunks) == 1
    line_types = [line.line_type for line in hunks[0].lines]
    assert line_types == ["remove", "no_newline", "add", "no_newline"]
    assert get_old_line_number(patch, 2) == 1
    assert get_new_line_number(patch, 4) == 1


def test_line_number_mapping_for_complex_patch() -> None:
    patch = """@@ -5,4 +5,5 @@
 keep_a
-remove_b
+add_b
+add_c
 keep_d
"""

    assert get_old_line_number(patch, 2) == 5
    assert get_old_line_number(patch, 3) == 6
    assert get_old_line_number(patch, 4) is None
    assert get_new_line_number(patch, 2) == 5
    assert get_new_line_number(patch, 3) is None
    assert get_new_line_number(patch, 4) == 6
    assert get_new_line_number(patch, 5) == 7
    assert get_old_line_number(patch, 99) is None


def test_parse_hunk_header_supports_default_count() -> None:
    assert _parse_hunk_header("@@ -8 +21 @@") == (8, 1, 21, 1)


def test_parse_hunk_header_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="无法解析 hunk 头"):
        _parse_hunk_header("@@ invalid @@")


def test_parse_diff_supports_multiple_files() -> None:
    diff_text = """diff --git a/a.py b/a.py
index 1111111..2222222 100644
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-a
+b
diff --git a/b.py b/b.py
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/b.py
@@ -0,0 +1 @@
+c
"""

    diff = parse_diff(diff_text)

    assert [item.status for item in diff.files] == ["modified", "added"]
    assert len(diff.files[0].hunks) == 1
    assert len(diff.files[1].hunks) == 1
