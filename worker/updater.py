import math
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

from games import EXE_SUFFIX

try:
    import requests
except ImportError:
    from packages import requests

start_dir = Path().cwd()

WORKER_URL = "https://github.com/official-stockfish/fishtest/archive/master.zip"


def do_restart():
    """Restarts the worker, using the same arguments"""
    args = sys.argv[:]
    args.insert(0, sys.executable)
    if sys.platform == "win32":
        args = [f'"{arg}"' for arg in args]

    os.chdir(start_dir)
    os.execv(sys.executable, args)  # This does not return!


def update(restart=True, test=False):
    worker_dir = Path(__file__).resolve().parent
    update_dir = Path(tempfile.mkdtemp(dir=worker_dir))
    worker_zip = update_dir / "wk.zip"

    try:
        response = requests.get(WORKER_URL)
        response.raise_for_status()
    except Exception as e:
        print(
            f"Failed to download {WORKER_URL}:\n",
            e,
            sep="",
            file=sys.stderr,
        )
        shutil.rmtree(update_dir)
        return None
    else:
        with open(worker_zip, "wb+") as f:
            f.write(response.content)

    with ZipFile(worker_zip) as zip_file:
        zip_file.extractall(update_dir)
    prefix = os.path.commonprefix([n.filename for n in zip_file.infolist()])
    worker_src = update_dir / prefix / "worker"
    from worker import (  # we do the import here to avoid issues with circular imports
        verify_sri,
    )

    if not verify_sri(worker_src):
        shutil.rmtree(update_dir)
        return None
    if not test:
        # Delete the "packages" folder to only have new files after an upgrade.
        packages_dir = worker_dir / "packages"
        if packages_dir.exists():
            try:
                shutil.rmtree(packages_dir)
            except Exception as e:
                print(
                    f"Failed to delete the folder {packages_dir}:\n",
                    e,
                    sep="",
                    file=sys.stderr,
                )
        if sys.version_info < (3, 8):
            from distutils.dir_util import copy_tree

            copy_tree(str(worker_src), str(worker_dir))
        else:
            shutil.copytree(worker_src, worker_dir, dirs_exist_ok=True)

    else:
        file_list = os.listdir(worker_src)
    shutil.rmtree(update_dir)

    # Rename the testing_dir to backup possible user custom files
    # and to trigger the download of updated files.
    # The worker runs games from the "testing" folder so change the folder.
    os.chdir(worker_dir)
    testing_dir = worker_dir / "testing"
    if testing_dir.exists():
        time_stamp = str(datetime.now(timezone.utc).timestamp())
        bkp_testing_dir = worker_dir / ("_testing_" + time_stamp)
        testing_dir.replace(bkp_testing_dir)
        testing_dir.mkdir()

        # Preserve/delete some old files
        backup_pattern = (
            # (pattern, num_bkps, expiration_in_days)
            ("fastchess" + EXE_SUFFIX, 1, math.inf),
            ("stockfish-*-old" + EXE_SUFFIX, 0, -1),
            ("stockfish-*" + EXE_SUFFIX, 50, 30),
            ("nn-*.nnue", 10, 30),
            ("results-*.pgn", 0, -1),
            ("*.epd", 4, 30),
            ("*.pgn", 4, 30),
        )
        for pattern, num_bkps, expiration_days in backup_pattern:
            expiration_time = time.time() - 24 * 3600 * expiration_days
            # the worker updates atime while validating files, so this works
            # on modern Linux systems which update atime very lazily
            for idx, path in enumerate(
                sorted(
                    bkp_testing_dir.glob(pattern), key=os.path.getatime, reverse=True
                )
            ):
                try:
                    if idx >= num_bkps:
                        path.unlink()
                    elif os.stat(path).st_atime < expiration_time:
                        path.unlink()
                    else:
                        # str(...) is necessary for compatibility with
                        # Python 3.6
                        shutil.move(str(path), testing_dir)
                except Exception as e:
                    print(
                        f"Failed to preserve/delete the file {path}:\n",
                        e,
                        sep="",
                        file=sys.stderr,
                    )
        # Clean up old folder backups (keeping the num_bkps most recent).
        num_bkps = 3
        for old_bkp_dir in sorted(
            worker_dir.glob("_testing_*"), key=os.path.getmtime, reverse=True
        )[num_bkps:]:
            try:
                shutil.rmtree(old_bkp_dir)
            except Exception as e:
                print(
                    f"Failed to remove the old backup folder {old_bkp_dir}:\n",
                    e,
                    sep="",
                    file=sys.stderr,
                )

    print(f"start_dir: {start_dir}")
    if restart:
        do_restart()

    if test:
        return file_list


if __name__ == "__main__":
    update(False)
