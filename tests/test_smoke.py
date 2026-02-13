from pathlib import Path
import json

def test_run_outputs_exist():
    # This test is illustrative; in CI it will run after the pipeline smoke test.
    root = Path(__file__).resolve().parents[1]
    manifest = root / "data" / "outputs" / "json" / "run_manifest.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["num_contracts"] >= 1
