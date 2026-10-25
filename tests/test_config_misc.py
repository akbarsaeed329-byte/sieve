import pytest

from sieve.config import apply_update, load_settings
from sieve.errors import SieveError
from sieve.pipeline import playbooks
from sieve.pipeline.normalise import normalise


def test_override_file_merges_but_cannot_enable_active_response(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"data_dir: {tmp_path}\nfilter: {{min_level: 4}}\n")
    (tmp_path / "settings.override.yaml").write_text("filter: {min_level: 7}\nallow_active_response: true\n")
    s = load_settings(str(cfg))
    assert s.filter.min_level == 7 and s.allow_active_response is False


def test_apply_update_rejects_bad_values(settings):
    with pytest.raises(SieveError):
        apply_update(settings, {"grouping": {"window_minutes": 0}})
    new, _ = apply_update(settings, {"llm": {"providers": []}})
    assert new.llm.providers == []


def test_normalise_rejects_hostile_entities():
    n = normalise({"rule": {"id": 1, "description": "Logon $(user)"}, "agent": {"name": "w"},
                   "data": {"srcip": "1.2.3.4 OR 1=1", "dstuser": "<script>alert(1)</script>"}})
    assert n.srcip is None and n.user is None
    assert {"data.srcip", "data.dstuser", "rule.description"} <= set(n.untrusted)


def test_playbook_templates_only_substitute_known_vars():
    pb = playbooks.render("PB-BRUTE", None, "1.2.3.4", None)
    assert "1.2.3.4" in pb["steps"][1]["detail"] and "the host" in pb["steps"][1]["detail"]
    assert playbooks._Safe().format("{user.__init__.__globals__}", user="x") == "{user.__init__.__globals__}"


def test_all_playbooks_load():
    assert set(playbooks.ids()) == {"PB-BRUTE", "PB-EXEC", "PB-GENERIC", "PB-NEWADMIN", "PB-WEBSCAN"}


def test_error_code_docs_in_sync():
    from pathlib import Path

    import sieve.errors as e
    doc = (Path(__file__).parents[1] / "docs" / "ERROR_CODES.md").read_text()
    codes = {v for k, v in vars(e).items() if k.isupper() and isinstance(v, str) and v.startswith("SIEVE-")}
    assert all(f"| {c} |" in doc for c in codes)
    assert all(c in e.FIXES for c in codes)
