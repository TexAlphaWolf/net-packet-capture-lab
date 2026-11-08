# Contributing

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest -n auto --cov
```

Reference packets in `tests/fixtures.py` were built with scapy, an implementation that shares no code with pcaplab;
keep it that way (do not generate expected values with pcaplab's own builders for decoding tests). Behaviour of the
detectors is tested on captures whose content is known (`pcaplab.synth`). After a change to `detect.py`, run
`python tools/evaluate.py --check`: it fails if a detector misses something that was injected or reports something that
was not. Do not tune thresholds on the seeds the report uses (1000 and above).

Claims in the docs are checked against `docs/report.json` by `tests/test_docs.py`. Re-run
`python tools/evaluate.py --real DIR --out docs/report.json`, then `python tools/make_evaluation_doc.py`, and update the
README when the numbers change. The captures in `DIR` are taken from the Wireshark test suite and are not stored in
this repository (the list is in `docs/evaluation.md`).
