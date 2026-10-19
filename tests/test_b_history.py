"""Stream B store/history_core.c: aggregation, rings, relative/absolute queries (decimation, gaps,
stage seconds, row iteration), daily files (append, torn tail, foreign header, retention) and reload."""
from b_store.harness import b_objs, run_c  # noqa: F401  (fixtures)


def test_history_c(b_objs, tmp_path):
    base = tmp_path / 'hist'
    base.mkdir()
    run_c(b_objs, tmp_path, 't_history', base)
