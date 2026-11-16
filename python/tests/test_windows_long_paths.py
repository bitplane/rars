import os
import shutil
from pathlib import Path

import pytest
import rars

pytestmark = pytest.mark.skipif(os.name != "nt", reason="MAX_PATH is a Windows limit")

VERBATIM = "\\\\?\\"


def verbatim(path):
    return Path(VERBATIM + str(path))


@pytest.fixture
def deep_dir(tmp_path):
    # Python's own file calls need the prefix past MAX_PATH unless long paths are enabled.
    root = verbatim(tmp_path.resolve() / "long")
    deep = root.joinpath(*(f"{index:02}" + "x" * 48 for index in range(6)))
    yield Path(str(deep)[len(VERBATIM):])
    shutil.rmtree(root)


@pytest.mark.parametrize("form", ["plain", "verbatim"])
def test_paths_past_max_path_write_open_and_extract(deep_dir, form):
    base = verbatim(deep_dir) if form == "verbatim" else deep_dir
    assert len(str(deep_dir)) > 260
    verbatim(deep_dir).mkdir(parents=True)

    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "nested/dir/file.txt")
    builder.write(base / "archive.rar")

    rar = rars.RarFile(base / "archive.rar")
    written = rar.extractall(base / "out")

    expected = base / "out" / "nested" / "dir" / "file.txt"
    assert written == [expected]
    assert verbatim(deep_dir / "out" / "nested" / "dir" / "file.txt").read_bytes() == b"payload"
