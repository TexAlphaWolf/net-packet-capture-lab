"""Render docs/demo.png: the HTML report of a SYNTHETIC capture (no real traffic is needed to show the page).

pip install -e ".[dev]" && playwright install chromium
python tools/screenshot.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

from playwright.sync_api import sync_playwright  # noqa: E402

from conftest import analyze_frames  # noqa: E402
from pcaplab.detect import detect  # noqa: E402
from pcaplab.report import html_page  # noqa: E402
from pcaplab.synth import build_scenario  # noqa: E402

OUT = ROOT / "docs" / "demo.png"


def main() -> None:
    frames, _truth = build_scenario(7, 1800.0)
    result = analyze_frames(frames)
    html = html_page(result, detect(result), "Capture report: demo.pcap", "synthetic capture, pcaplab sample --seed 7")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1000, "height": 1400}, device_scale_factor=2)
        page.set_content(html)
        page.screenshot(path=str(OUT), clip={"x": 0, "y": 0, "width": 1000, "height": 1250})
        browser.close()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
