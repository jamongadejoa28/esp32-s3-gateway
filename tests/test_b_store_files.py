"""Stream B store pure file/secrets code: atomic_file.c on a real directory, secrets.c model + JSON."""
import tempfile

from b_store.harness import b_objs, run_c  # noqa: F401  (fixtures)


def test_atomic_file_c(b_objs, tmp_path):
    # ATOMIC_PATH_MAX (64) is a device constraint: use a short directory so "<dir>/cfg.json.tmp" fits.
    with tempfile.TemporaryDirectory(prefix='gwb') as d:
        run_c(b_objs, tmp_path, 't_atomic', d)


def test_secrets_c(b_objs, tmp_path):
    run_c(b_objs, tmp_path, 't_secrets')
