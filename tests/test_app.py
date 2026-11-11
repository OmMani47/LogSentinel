"""The review page shows the disclaimer, an alert, and the stealth miss."""

from streamlit.testing.v1 import AppTest


def test_sample_log_shows_the_disclaimer_and_the_known_miss():
    app = AppTest.from_file("src/app.py", default_timeout=90)
    app.run()
    assert not app.exception, app.exception

    captions = " ".join(block.value for block in app.caption).lower()
    assert "not an estimate of accuracy on real authentication logs" in captions
    assert "no earlier success" in captions

    markdown = " ".join(block.value for block in app.markdown)
    assert "stealth-test-1" in markdown
    assert "slow-brute-test-1" in markdown
    assert "Isolation Forest" in markdown or "failed" in markdown.lower()
