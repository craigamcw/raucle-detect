"""Tests for the raucle.com release-sync script."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sync_website  # noqa: E402

_CHANGELOG = textwrap.dedent("""\
    # Changelog

    ## 0.4.0 (2026-05-13)

    ### New Features

    - **Tamper-evident audit chain** (`HashChainSink`) — every event SHA-256
      linked to its predecessor; Ed25519 signed checkpoints.
    - **Signed JWS verdict receipts** (`VerdictSigner`) — downstream-verifiable.
    - **Outcome verification** — LANDED, REFUSED, or UNCERTAIN.

    ### Compliance

    - EU AI Act Article 12 ready.

    ## 0.3.0 (2026-05-12)

    ### New Features

    - **Old feature** — this should not appear in 0.4.0 output.
    """)


_HTML_TEMPLATE = textwrap.dedent("""\
    <html>
    <body>
        <section>
            <!-- RAUCLE_DETECT:VERSION:START -->
            <p>old version</p>
            <!-- RAUCLE_DETECT:VERSION:END -->
            <p>The detection engine.</p>
            <!-- RAUCLE_DETECT:FEATURES:START -->
            <ul><li>old feature</li></ul>
            <!-- RAUCLE_DETECT:FEATURES:END -->
            <!-- RAUCLE_DETECT:WHATSNEW:START -->
            <!-- RAUCLE_DETECT:WHATSNEW:END -->
        </section>
    </body>
    </html>
    """)


class TestParseChangelog:
    def test_extracts_target_version_only(self):
        notes = sync_website.parse_changelog(_CHANGELOG, "0.4.0")
        assert notes.version == "0.4.0"
        assert "Old feature" not in " ".join(notes.headline_features)

    def test_collects_section_titles(self):
        notes = sync_website.parse_changelog(_CHANGELOG, "0.4.0")
        assert "New Features" in notes.section_titles
        assert "Compliance" in notes.section_titles

    def test_headline_features_use_bold_phrase(self):
        notes = sync_website.parse_changelog(_CHANGELOG, "0.4.0")
        assert any("Tamper-evident audit chain" in f for f in notes.headline_features)
        assert any("Signed JWS verdict receipts" in f for f in notes.headline_features)

    def test_missing_version_raises(self):
        import pytest

        with pytest.raises(SystemExit, match="not found"):
            sync_website.parse_changelog(_CHANGELOG, "9.9.9")

    def test_backticks_inside_bold_phrase_stripped(self):
        """Regression: ``**`AgentIdentity`** — …`` should produce a clean
        feature name ``AgentIdentity`` with no literal backticks rendered."""
        changelog_with_code_bold = (
            "## 0.5.0 (2026-05-14)\n\n"
            "### New Features\n\n"
            "- **`AgentIdentity`** — Ed25519 keypair plus a signed statement.\n"
        )
        notes = sync_website.parse_changelog(changelog_with_code_bold, "0.5.0")
        joined = " ".join(notes.headline_features)
        assert "AgentIdentity" in joined
        assert "`" not in joined


class TestRendering:
    def test_version_badge_html_escaped(self):
        out = sync_website.render_version_badge("0.4.0")
        assert "v0.4.0" in out
        assert 'class="release-badge"' in out

    def test_features_list_renders_items(self):
        out = sync_website.render_features_list(["Feature A", "Feature B & C"])
        assert "Feature A" in out
        assert "Feature B &amp; C" in out  # HTML-escaped
        assert out.count("<li>") == 2

    def test_features_list_empty_uses_placeholder(self):
        out = sync_website.render_features_list([])
        assert "<li>" in out  # still renders a fallback bullet

    def test_whatsnew_includes_link_and_titles(self):
        out = sync_website.render_whatsnew(
            "0.4.0",
            ["New Features", "Compliance"],
            "https://github.com/example/repo",
        )
        assert "v0.4.0" in out
        assert "New Features" in out
        assert "https://github.com/example/repo/blob/main/CHANGELOG.md" in out


class TestEndToEnd:
    def test_full_sync_replaces_all_three_blocks(self, tmp_path):
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        website_path = tmp_path / "index.html"
        website_path.write_text(_HTML_TEMPLATE)

        rc = sync_website.main(
            [
                "--changelog",
                str(changelog_path),
                "--version",
                "0.4.0",
                "--website-html",
                str(website_path),
            ]
        )
        assert rc == 0

        result = website_path.read_text()
        assert "v0.4.0" in result
        assert "Tamper-evident audit chain" in result
        assert "old version" not in result
        assert "old feature" not in result
        assert "What's new in v0.4.0" in result

    def test_idempotent(self, tmp_path):
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        website_path = tmp_path / "index.html"
        website_path.write_text(_HTML_TEMPLATE)

        args = [
            "--changelog",
            str(changelog_path),
            "--version",
            "0.4.0",
            "--website-html",
            str(website_path),
        ]
        sync_website.main(args)
        once = website_path.read_text()
        sync_website.main(args)
        twice = website_path.read_text()
        assert once == twice

    def test_missing_marker_raises(self, tmp_path):
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        broken_html = "<html><body>no markers here</body></html>"
        website_path = tmp_path / "index.html"
        website_path.write_text(broken_html)

        import pytest

        with pytest.raises(SystemExit, match="markers RAUCLE_DETECT:VERSION"):
            sync_website.main(
                [
                    "--changelog",
                    str(changelog_path),
                    "--version",
                    "0.4.0",
                    "--website-html",
                    str(website_path),
                ]
            )
