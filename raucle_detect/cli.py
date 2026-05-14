"""Raucle Detect command-line interface.

Examples::

    raucle-detect scan "Ignore all previous instructions"
    raucle-detect scan --file prompts.txt --format json
    raucle-detect scan --mode strict "reveal your system prompt"
    raucle-detect serve --port 8000
    raucle-detect rules list
    raucle-detect rules list --rules-dir ./my-rules/
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from raucle_detect import __version__
from raucle_detect.scanner import MAX_INPUT_BYTES, Scanner

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raucle-detect",
        description="Raucle Detect -- prompt injection detection for LLM applications",
    )
    parser.add_argument("--version", action="version", version=f"raucle-detect {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- scan ---------------------------------------------------------------
    scan_p = subparsers.add_parser("scan", help="Scan prompts for injection attacks")
    scan_p.add_argument("text", nargs="?", help="Prompt text to scan")
    scan_p.add_argument("--file", "-f", type=str, help="Read prompts from a file (one per line)")
    _modes = ["strict", "standard", "permissive"]
    scan_p.add_argument(
        "--mode",
        "-m",
        choices=_modes,
        default="standard",
    )
    scan_p.add_argument(
        "--rules-dir",
        "-r",
        type=str,
        help="Path to custom YAML rules directory",
    )
    scan_p.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )

    # -- scan-image / scan-pdf / scrub (multimodal v0.7.0) ------------------
    scan_image = subparsers.add_parser(
        "scan-image", help="Scan an image: OCR + EXIF + scrub then text-scan"
    )
    scan_image.add_argument("path", help="Path to the image file")
    scan_image.add_argument("--mode", "-m", choices=_modes, default="standard")
    scan_image.add_argument(
        "--rules-dir", "-r", type=str, help="Path to custom YAML rules directory"
    )
    scan_image.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )

    scan_pdf = subparsers.add_parser(
        "scan-pdf", help="Scan a PDF: extract text + scrub then text-scan"
    )
    scan_pdf.add_argument("path", help="Path to the PDF file")
    scan_pdf.add_argument("--mode", "-m", choices=_modes, default="standard")
    scan_pdf.add_argument("--rules-dir", "-r", type=str, help="Path to custom YAML rules directory")
    scan_pdf.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )

    scrub = subparsers.add_parser(
        "scrub", help="Inspect text for invisible / formatting Unicode chars"
    )
    scrub.add_argument("text", nargs="?", help="Text to inspect (or use --file)")
    scrub.add_argument("--file", "-f", type=str, help="Read text from a file")
    scrub.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # -- serve --------------------------------------------------------------
    serve_p = subparsers.add_parser("serve", help="Start the REST API server")
    serve_p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1)",
    )
    serve_p.add_argument(
        "--port",
        "-p",
        type=int,
        default=8000,
        help="Port (default: 8000)",
    )
    serve_p.add_argument(
        "--mode",
        "-m",
        choices=_modes,
        default="standard",
    )
    serve_p.add_argument(
        "--rules-dir",
        "-r",
        type=str,
        help="Path to custom YAML rules directory",
    )

    # -- rules --------------------------------------------------------------
    rules_p = subparsers.add_parser("rules", help="Manage detection rules")
    rules_sub = rules_p.add_subparsers(dest="rules_command")
    rules_list = rules_sub.add_parser("list", help="List all loaded rules")
    rules_list.add_argument(
        "--rules-dir",
        "-r",
        type=str,
        help="Path to custom YAML rules directory",
    )
    rules_list.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )

    # -- rules fuzz ---------------------------------------------------------
    rules_fuzz = rules_sub.add_parser(
        "fuzz",
        help="Mutation-test rules against adversarial variants",
    )
    rules_fuzz.add_argument(
        "--rules-dir",
        "-r",
        type=str,
        help="Path to custom YAML rules directory",
    )
    rules_fuzz.add_argument(
        "--samples",
        type=int,
        default=3,
        help="Variants per seed per strategy (default: 3)",
    )
    rules_fuzz.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )
    rules_fuzz.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility",
    )

    # -- audit --------------------------------------------------------------
    audit_p = subparsers.add_parser("audit", help="Audit chain operations")
    audit_sub = audit_p.add_subparsers(dest="audit_command")

    audit_verify = audit_sub.add_parser("verify", help="Verify an audit chain file")
    audit_verify.add_argument("path", help="Path to the chain log (JSONL)")
    audit_verify.add_argument(
        "--pubkey",
        type=str,
        help="Path to Ed25519 public key PEM (omit to skip signature verification)",
    )
    audit_verify.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )

    audit_keygen = audit_sub.add_parser(
        "keygen", help="Generate a new Ed25519 audit key pair (writes PEM files)"
    )
    audit_keygen.add_argument(
        "--out", default="raucle-audit", help="Output prefix (default: raucle-audit)"
    )

    # -- verify-receipt -----------------------------------------------------
    receipt_p = subparsers.add_parser("verify-receipt", help="Verify a signed JWS verdict receipt")
    receipt_p.add_argument("receipt", help="The compact JWS receipt string")
    receipt_p.add_argument("--pubkey", required=True, help="Path to Ed25519 public key PEM")
    receipt_p.add_argument("--input", help="Expected original prompt (binds receipt to input)")

    # -- mcp ----------------------------------------------------------------
    mcp_p = subparsers.add_parser("mcp", help="Model Context Protocol operations")
    mcp_sub = mcp_p.add_subparsers(dest="mcp_command")

    mcp_serve = mcp_sub.add_parser("serve", help="Run raucle as an MCP server over stdio")
    mcp_serve.add_argument(
        "--mode",
        choices=_modes,
        default="standard",
        help="Detection sensitivity for the underlying scanner",
    )
    mcp_serve.add_argument(
        "--rules-dir", "-r", type=str, help="Path to custom YAML rules directory"
    )

    mcp_scan = mcp_sub.add_parser("scan", help="Static analysis of an MCP server manifest")
    mcp_scan.add_argument("path", help="Manifest JSON file or directory of manifests")
    mcp_scan.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (sarif suitable for GitHub Advanced Security)",
    )
    mcp_scan.add_argument("--sarif-out", help="Write SARIF output to this file")

    # -- provenance ---------------------------------------------------------
    prov_p = subparsers.add_parser(
        "provenance",
        help="AI Provenance Graph — emit and verify signed receipts across agents/tools/models",
    )
    prov_sub = prov_p.add_subparsers(dest="provenance_command")

    prov_keygen = prov_sub.add_parser(
        "keygen", help="Generate a new agent identity (keypair + capability statement)"
    )
    prov_keygen.add_argument("agent_id", help="Agent identifier, e.g. 'agent:billing-summariser'")
    prov_keygen.add_argument("--out", default=None, help="Output prefix (default: <agent_id>)")
    prov_keygen.add_argument(
        "--allowed-models",
        nargs="*",
        default=[],
        help="Models this agent may call (omit for unrestricted)",
    )
    prov_keygen.add_argument(
        "--allowed-tools",
        nargs="*",
        default=[],
        help="Tools this agent may call (omit for unrestricted)",
    )
    prov_keygen.add_argument(
        "--ttl-days",
        type=int,
        default=None,
        help="Capability statement TTL in days (omit for non-expiring)",
    )

    prov_verify = prov_sub.add_parser("verify", help="Verify a provenance chain")
    prov_verify.add_argument("path", help="JSONL chain file")
    prov_verify.add_argument(
        "--pubkeys",
        nargs="+",
        required=True,
        help="One or more capability-statement JSON files OR public-key PEM files",
    )
    prov_verify.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )

    prov_trace = prov_sub.add_parser(
        "trace", help="Walk the DAG backwards from a receipt to all roots"
    )
    prov_trace.add_argument("receipt_hash", help="The leaf receipt to trace from")
    prov_trace.add_argument("--chain", required=True, help="JSONL chain file")
    prov_trace.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )

    prov_graph = prov_sub.add_parser(
        "graph", help="Export the ancestor DAG of a receipt as Graphviz DOT"
    )
    prov_graph.add_argument("receipt_hash", help="The leaf receipt to render")
    prov_graph.add_argument("--chain", required=True, help="JSONL chain file")
    prov_graph.add_argument("--out", help="Write DOT to file (default: stdout)")

    prov_replay = prov_sub.add_parser(
        "replay",
        help="Counterfactual replay — re-run a chain against an alternate policy",
    )
    prov_replay.add_argument("chain", help="Path to the provenance chain JSONL")
    prov_replay.add_argument(
        "--input-store",
        required=True,
        help="Path to the input-store JSONL produced alongside the chain",
    )
    prov_replay.add_argument(
        "--mode",
        choices=_modes,
        default="strict",
        help="Counterfactual scanner mode (default: strict)",
    )
    prov_replay.add_argument(
        "--rules-dir",
        "-r",
        type=str,
        help="Optional custom YAML rules directory for the counterfactual scan",
    )
    prov_replay.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )
    prov_replay.add_argument(
        "--show-unchanged",
        action="store_true",
        help="Include receipts whose verdict did not change in the output",
    )

    # ---- Federated signed-IOC feeds (v0.8.0) -----------------------------
    feed_p = subparsers.add_parser(
        "feed",
        help="Federated signed-IOC feeds — publish, verify, and subscribe",
    )
    feed_sub = feed_p.add_subparsers(dest="feed_command")

    feed_keygen = feed_sub.add_parser("keygen", help="Generate an issuer Ed25519 keypair")
    feed_keygen.add_argument("issuer", help="Issuer name, e.g. 'raucle.io'")
    feed_keygen.add_argument("--out", default="issuer", help="Output prefix (default: 'issuer')")

    feed_sign = feed_sub.add_parser(
        "sign", help="Sign a JSON list of IOC drafts into a published feed"
    )
    feed_sign.add_argument("drafts", help="Path to JSON file: list of IOC drafts")
    feed_sign.add_argument("--key", required=True, help="Issuer private-key PEM")
    feed_sign.add_argument("--issuer", required=True, help="Issuer name (must match key)")
    feed_sign.add_argument("--feed-id", required=True, help="Feed identifier, e.g. 'raucle/core'")
    feed_sign.add_argument("--out", required=True, help="Output feed JSON path")

    feed_verify = feed_sub.add_parser("verify", help="Verify a feed against a pinned pubkey")
    feed_verify.add_argument("feed", help="Path to feed JSON")
    feed_verify.add_argument(
        "--pubkey", help="Path to pinned public-key PEM (omit to skip pinning check)"
    )

    feed_pull = feed_sub.add_parser(
        "pull", help="Fetch a feed over HTTPS, verify, and merge into the local store"
    )
    feed_pull.add_argument("url", help="HTTPS URL of the feed JSON")
    feed_pull.add_argument(
        "--pubkey", required=True, help="Path to pinned public-key PEM for the issuer"
    )
    feed_pull.add_argument(
        "--store",
        default="~/.raucle/feeds",
        help="Local feed store directory (default: ~/.raucle/feeds)",
    )

    feed_list = feed_sub.add_parser("list", help="List IOCs in the local feed store")
    feed_list.add_argument(
        "--store",
        default="~/.raucle/feeds",
        help="Local feed store directory (default: ~/.raucle/feeds)",
    )

    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_with_count(raw: bytes, encoding: str = "utf-8") -> tuple[str, int]:
    """Decode *raw* bytes, replacing invalid sequences and counting replacements."""
    decoded = raw.decode(encoding, errors="replace")
    error_count = decoded.count("�")
    return decoded, error_count


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def _print_result_table(result, index: int | None = None) -> None:
    prefix = f"[{index}] " if index is not None else ""
    verdict_display = result.verdict
    if result.verdict == "MALICIOUS":
        verdict_display = f"\033[91m{result.verdict}\033[0m"
    elif result.verdict == "SUSPICIOUS":
        verdict_display = f"\033[93m{result.verdict}\033[0m"
    else:
        verdict_display = f"\033[92m{result.verdict}\033[0m"

    print(f"{prefix}Verdict:    {verdict_display}")
    print(f"{prefix}Confidence: {result.confidence:.1%}")
    print(f"{prefix}Action:     {result.action}")
    if result.categories:
        print(f"{prefix}Categories: {', '.join(result.categories)}")
    if result.attack_technique:
        print(f"{prefix}Technique:  {result.attack_technique}")
    if result.matched_rules:
        print(f"{prefix}Rules:      {', '.join(result.matched_rules)}")
    print(
        f"{prefix}Layers:     pattern={result.layer_scores.get('pattern', 0):.4f}  "
        f"semantic={result.layer_scores.get('semantic', 0):.4f}"
    )


def _print_rules_table(rules: list[dict]) -> None:
    if not rules:
        print("No rules loaded.")
        return
    header = f"{'ID':<10} {'Name':<30} {'Category':<25} {'Severity':<10} {'Patterns':>8}"
    print(header)
    print("-" * len(header))
    for r in rules:
        print(
            f"{r['id']:<10} {r['name']:<30} {r['category']:<25} "
            f"{r['severity']:<10} {r['pattern_count']:>8}"
        )
    print(f"\nTotal: {len(rules)} rules")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _cmd_scan(args: argparse.Namespace) -> int:
    scanner = Scanner(mode=args.mode, rules_dir=args.rules_dir)

    prompts: list[str] = []
    if args.text:
        prompts.append(args.text)
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            return 1
        file_size = file_path.stat().st_size
        if file_size > MAX_INPUT_BYTES:
            print(
                f"Warning: file is {file_size:,} bytes, exceeding the "
                f"{MAX_INPUT_BYTES:,}-byte limit. Input will be truncated.",
                file=sys.stderr,
            )
        raw_bytes = file_path.read_bytes()[:MAX_INPUT_BYTES]
        raw, encoding_errors = _decode_with_count(raw_bytes)
        if encoding_errors:
            print(
                f"Warning: {encoding_errors} invalid byte(s) in {args.file} were replaced "
                "with �. Scan results may not reflect the original content.",
                file=sys.stderr,
            )
        prompts = [line.strip() for line in raw.splitlines() if line.strip()]
    else:
        # Read from stdin
        if sys.stdin.isatty():
            print("Reading from stdin (Ctrl+D to finish):", file=sys.stderr)
        prompts = [line.strip() for line in sys.stdin if line.strip()]

    if not prompts:
        print("Error: no input provided.", file=sys.stderr)
        return 1

    results = scanner.scan_batch(prompts) if len(prompts) > 1 else [scanner.scan(prompts[0])]

    if args.format == "json":
        output = [r.to_dict() for r in results]
        print(json.dumps(output if len(output) > 1 else output[0], indent=2))
    else:
        for i, result in enumerate(results):
            if len(results) > 1:
                _print_result_table(result, index=i)
                print()
            else:
                _print_result_table(result)

    # Exit code: 2 if any malicious, 1 if any suspicious, 0 if clean
    if any(r.verdict == "MALICIOUS" for r in results):
        return 2
    if any(r.verdict == "SUSPICIOUS" for r in results):
        return 1
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn  # type: ignore[import-untyped]
    except ImportError:
        print(
            "Error: uvicorn is required for the server.\n"
            "Install it with:  pip install raucle-detect[server]",
            file=sys.stderr,
        )
        return 1

    # Store config in environment for the server module to pick up
    import os

    os.environ["RAUCLE_DETECT_MODE"] = args.mode
    if args.rules_dir:
        os.environ["RAUCLE_DETECT_RULES_DIR"] = args.rules_dir

    print(f"Starting Raucle Detect server on {args.host}:{args.port} (mode={args.mode})")
    uvicorn.run(
        "raucle_detect.server:app",
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    scanner = Scanner(rules_dir=args.rules_dir)
    rules = scanner.list_rules()

    if args.format == "json":
        print(json.dumps(rules, indent=2))
    else:
        _print_rules_table(rules)
    return 0


def _cmd_rules_fuzz(args: argparse.Namespace) -> int:
    from raucle_detect.mutator import RuleFuzzer

    scanner = Scanner(rules_dir=args.rules_dir)
    fuzzer = RuleFuzzer(
        scanner,
        samples_per_seed=args.samples,
        random_seed=args.seed,
    )

    print("Running rule mutation fuzzer...", file=sys.stderr)
    report = fuzzer.fuzz()

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        # Table output
        print(
            f"\nOverall coverage: {report.overall_coverage:.0%} "
            f"({report.total_caught}/{report.total_variants} variants detected)"
        )
        print(f"Strategies: {', '.join(report.strategies_tested)}\n")
        header = f"{'Rule ID':<12} {'Coverage':>9} {'Caught':>7} {'Total':>7}  Missed strategies"
        print(header)
        print("-" * len(header))
        for entry in report.results:
            missed_str = ", ".join(entry.missed_strategies) if entry.missed_strategies else "—"
            cov_str = f"{entry.coverage:.0%}"
            cov_colored = (
                f"\033[91m{cov_str}\033[0m"
                if entry.coverage < 0.5
                else f"\033[93m{cov_str}\033[0m"
                if entry.coverage < 0.8
                else f"\033[92m{cov_str}\033[0m"
            )
            print(
                f"{entry.rule_id:<12} {cov_colored:>18} {entry.caught:>7} "
                f"{entry.total:>7}  {missed_str}"
            )
        print()
        # Highlight rules with low coverage
        weak = [e for e in report.results if e.coverage < 0.5]
        if weak:
            print(
                f"⚠ {len(weak)} rule(s) with <50% variant coverage — consider expanding patterns:"
            )
            for e in weak:
                print(f"  {e.rule_id}: {e.coverage:.0%} — missed: {', '.join(e.missed_strategies)}")
                if e.sample_misses:
                    print(f"    Example miss: {e.sample_misses[0][:80]!r}")

    # Exit 1 if any rule has 0% coverage
    if any(e.coverage == 0.0 for e in report.results):
        return 1
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    from raucle_detect.audit import AuditVerifier

    pubkey_pem: bytes | None = None
    if args.pubkey:
        pubkey_pem = Path(args.pubkey).read_bytes()
    report = AuditVerifier(public_key_pem=pubkey_pem).verify_chain(args.path)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        status = "\033[92mVALID\033[0m" if report.valid else "\033[91mINVALID\033[0m"
        print(f"Audit chain: {status}")
        print(f"  Events:               {report.event_count}")
        print(f"  Checkpoints:          {report.checkpoint_count}")
        print(f"  Valid signatures:     {report.valid_signatures}")
        print(f"  Invalid signatures:   {report.invalid_signatures}")
        if report.first_invalid_index is not None:
            print(f"  First invalid index:  {report.first_invalid_index}")
        if report.errors:
            print("\nErrors:")
            for e in report.errors[:10]:
                print(f"  - {e}")
            if len(report.errors) > 10:
                print(f"  … and {len(report.errors) - 10} more")
    return 0 if report.valid else 2


def _cmd_audit_keygen(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization

    from raucle_detect.audit import Ed25519Signer

    signer = Ed25519Signer.generate()
    priv_path = Path(f"{args.out}-private.pem")
    pub_path = Path(f"{args.out}-public.pem")

    priv_pem = signer._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(signer.public_key_pem())
    priv_path.chmod(0o600)

    print("Generated key pair:")
    print(f"  Private key: {priv_path} (chmod 600)")
    print(f"  Public key:  {pub_path}")
    print(f"  Key ID:      {signer.key_id()}")
    print()
    print("Keep the private key secret. Distribute the public key to verifiers.")
    return 0


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    from raucle_detect.verdicts import VerdictVerificationError, VerdictVerifier

    pubkey_pem = Path(args.pubkey).read_bytes()
    verifier = VerdictVerifier(public_key_pem=pubkey_pem)
    try:
        payload = verifier.verify(args.receipt, expected_input=args.input)
    except VerdictVerificationError as exc:
        print(f"\033[91mINVALID\033[0m: {exc}", file=sys.stderr)
        return 2

    print("\033[92mVALID\033[0m receipt:")
    print(json.dumps(payload.to_dict(), indent=2))
    return 0


def _cmd_mcp_serve(args: argparse.Namespace) -> int:
    from raucle_detect.mcp_server import MCPServer

    scanner = Scanner(mode=args.mode, rules_dir=args.rules_dir)
    server = MCPServer(scanner=scanner)
    # Log to stderr only — stdout is the JSON-RPC channel
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(message)s")
    logger.info("raucle-detect MCP server starting (mode=%s)", args.mode)
    import contextlib

    with contextlib.suppress(KeyboardInterrupt):
        server.serve_stdio()
    return 0


def _cmd_mcp_scan(args: argparse.Namespace) -> int:
    from raucle_detect.mcp_scanner import (
        findings_to_sarif,
        scan_manifest_dir,
        scan_manifest_file,
    )

    path = Path(args.path)
    findings = scan_manifest_dir(path) if path.is_dir() else scan_manifest_file(path)

    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif args.format == "sarif":
        sarif = findings_to_sarif(findings, tool_version=__version__)
        if args.sarif_out:
            Path(args.sarif_out).write_text(json.dumps(sarif, indent=2))
            print(f"SARIF written to {args.sarif_out}", file=sys.stderr)
        else:
            print(json.dumps(sarif, indent=2))
    else:
        if not findings:
            print("No findings.")
        else:
            print(f"{len(findings)} finding(s):\n")
            header = f"{'Rule ID':<24} {'Severity':<10} {'Tool':<20} {'Field':<28} Message"
            print(header)
            print("-" * min(len(header), 120))
            for f in findings:
                colour = {
                    "CRITICAL": "\033[91m",
                    "HIGH": "\033[91m",
                    "MEDIUM": "\033[93m",
                    "LOW": "\033[93m",
                    "INFO": "\033[92m",
                }.get(f.severity.value, "")
                sev = f"{colour}{f.severity.value}\033[0m"
                print(f"{f.rule_id:<24} {sev:<19} {f.tool[:19]:<20} {f.field[:27]:<28} {f.message}")

    # Exit code: 2 if any CRITICAL/HIGH, 1 if any MEDIUM/LOW, 0 if clean
    if any(f.severity.value in ("CRITICAL", "HIGH") for f in findings):
        return 2
    if findings:
        return 1
    return 0


def _cmd_provenance_keygen(args: argparse.Namespace) -> int:
    from raucle_detect.provenance import AgentIdentity

    ttl = args.ttl_days * 86400 if args.ttl_days else None
    identity = AgentIdentity.generate(
        agent_id=args.agent_id,
        allowed_models=args.allowed_models,
        allowed_tools=args.allowed_tools,
        ttl_seconds=ttl,
    )

    prefix = args.out or args.agent_id.replace(":", "_").replace("/", "_")
    priv_path = Path(f"{prefix}-private.pem")
    stmt_path = Path(f"{prefix}-capability.json")

    priv_path.write_bytes(identity.private_key_pem())
    priv_path.chmod(0o600)
    stmt_path.write_text(json.dumps(identity.statement.to_dict(), indent=2))

    print("Generated agent identity:")
    print(f"  Agent ID:           {identity.agent_id}")
    print(f"  Key ID:             {identity.key_id}")
    print(f"  Private key:        {priv_path} (chmod 600)")
    print(f"  Capability stmt:    {stmt_path}")
    print(f"  Allowed models:     {identity.statement.allowed_models or 'unrestricted'}")
    print(f"  Allowed tools:      {identity.statement.allowed_tools or 'unrestricted'}")
    print()
    print("Distribute the capability statement to verifiers. Keep the private key secret.")
    return 0


def _cmd_provenance_verify(args: argparse.Namespace) -> int:
    from raucle_detect.provenance import CapabilityStatement, ProvenanceVerifier

    public_keys: dict[str, bytes] = {}
    for src in args.pubkeys:
        path = Path(src)
        content = path.read_bytes()
        # Try JSON capability statement first; fall back to raw PEM.
        try:
            d = json.loads(content)
            stmt = CapabilityStatement.from_dict(d)
            public_keys[stmt.key_id] = stmt.public_key_pem.encode("ascii")
        except (json.JSONDecodeError, KeyError):
            # Raw PEM — derive key_id from the bytes
            import hashlib

            key_id = hashlib.sha256(content).hexdigest()[:16]
            public_keys[key_id] = content

    report = ProvenanceVerifier(public_keys=public_keys).verify_chain(args.path)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        status = "\033[92mVALID\033[0m" if report.valid else "\033[91mINVALID\033[0m"
        print(f"Provenance chain: {status}")
        print(f"  Receipts:                  {report.receipt_count}")
        print(f"  Signature failures:        {report.signature_failures}")
        print(f"  Parent-link failures:      {report.parent_link_failures}")
        print(f"  Taint monotonicity fails:  {report.taint_monotonicity_failures}")
        if report.tampered_receipts:
            print(f"  Tampered receipts:         {len(report.tampered_receipts)}")
        if report.errors:
            print("\nErrors:")
            for e in report.errors[:10]:
                print(f"  - {e}")
            if len(report.errors) > 10:
                print(f"  … and {len(report.errors) - 10} more")

    return 0 if report.valid else 2


def _cmd_provenance_trace(args: argparse.Namespace) -> int:
    from raucle_detect.provenance import ProvenanceVerifier

    verifier = ProvenanceVerifier(public_keys={})  # signature check skipped here
    try:
        receipts = verifier.trace(args.receipt_hash, args.chain)
    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps([r.to_dict() for r in receipts], indent=2))
    else:
        print(f"\nDAG ancestors of {args.receipt_hash} ({len(receipts)} receipts):\n")
        header = f"{'Operation':<18} {'Agent':<32} {'Detail':<28} {'Receipt':<20}"
        print(header)
        print("-" * len(header))
        for r in receipts:
            detail_parts: list[str] = []
            if r.model:
                detail_parts.append(f"model={r.model}")
            if r.tool:
                detail_parts.append(f"tool={r.tool}")
            if r.corpus:
                detail_parts.append(f"corpus={r.corpus}")
            if r.guardrail_verdict:
                detail_parts.append(f"verdict={r.guardrail_verdict}")
            detail = ", ".join(detail_parts) or "—"
            short = r.receipt_hash.split(":")[-1][:16]
            print(f"{r.operation.value:<18} {r.agent_id[:31]:<32} {detail[:27]:<28} {short:<20}")
    return 0


def _cmd_provenance_graph(args: argparse.Namespace) -> int:
    from raucle_detect.provenance import ProvenanceVerifier

    verifier = ProvenanceVerifier(public_keys={})
    try:
        dot = verifier.to_dot(args.receipt_hash, args.chain)
    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.out:
        Path(args.out).write_text(dot)
        print(f"DOT graph written to {args.out}", file=sys.stderr)
    else:
        print(dot)
    return 0


def _cmd_provenance_replay(args: argparse.Namespace) -> int:
    from raucle_detect.replay import InputStore, Replayer
    from raucle_detect.scanner import Scanner

    store_path = Path(args.input_store)
    if not store_path.exists():
        print(f"Error: input store {args.input_store} does not exist", file=sys.stderr)
        return 1

    chain_path = Path(args.chain)
    if not chain_path.exists():
        print(f"Error: chain {args.chain} does not exist", file=sys.stderr)
        return 1

    with InputStore.open(store_path) as store:
        scanner = Scanner(mode=args.mode, rules_dir=args.rules_dir)
        policy_label_parts = [f"mode={args.mode}"]
        if args.rules_dir:
            policy_label_parts.append(f"rules_dir={args.rules_dir}")
        replayer = Replayer(scanner, store, policy_label=" + ".join(policy_label_parts))
        result = replayer.replay_chain(chain_path)

    if args.format == "json":
        out = result.to_dict()
        if args.show_unchanged:
            out["unchanged"] = [c.to_dict() for c in result.unchanged]
        print(json.dumps(out, indent=2))
        return 0

    summary = result.summary()
    print(f"\nCounterfactual replay against policy: {result.counterfactual_policy}")
    print(f"  Chain:                 {result.chain_path}")
    print(f"  Total receipts:        {summary['total_receipts']}")
    print(f"  Replayable scans:      {summary['replayed']}")
    print(f"  Missing-input scans:   {summary['missing_inputs']}")
    print(
        f"  Unchanged verdicts:    \033[92m{summary['unchanged']}\033[0m   "
        f"Changed: \033[93m{summary['changed']}\033[0m"
    )
    print(
        f"    Newly BLOCKed: \033[91m{summary['newly_blocked']}\033[0m   "
        f"Newly ALERTed: \033[93m{summary['newly_alerted']}\033[0m   "
        f"Newly ALLOWed: \033[92m{summary['newly_allowed']}\033[0m"
    )

    if result.changes:
        print("\nChanges:")
        print(f"  {'Receipt':<22} {'was':<10} {'→':<3} {'now':<10}  Explanation")
        print("  " + "-" * 78)
        for c in result.changes:
            short_hash = c.receipt_hash.split(":")[-1][:18]
            print(
                f"  {short_hash:<22} {c.original_action:<10} → "
                f"{c.counterfactual_action:<10}  {c.explanation}"
            )

    if args.show_unchanged and result.unchanged:
        print(f"\nUnchanged ({len(result.unchanged)}):")
        for c in result.unchanged:
            short_hash = c.receipt_hash.split(":")[-1][:18]
            print(f"  {short_hash:<22} {c.original_action:<10}  {c.explanation}")

    return 0


def _print_multimodal_result(result, path: str | None = None) -> None:
    """Render a MultimodalScanResult to stdout in table form."""
    verdict_colour = {
        "MALICIOUS": "\033[91m",
        "SUSPICIOUS": "\033[93m",
        "CLEAN": "\033[92m",
    }.get(result.combined_verdict, "")
    if path:
        print(f"Input:       {path}")
    print(
        f"Verdict:     {verdict_colour}{result.combined_verdict}\033[0m   "
        f"Action: {result.combined_action}"
    )
    if result.findings:
        print(f"\nFindings ({len(result.findings)}):")
        for f in result.findings:
            sev_colour = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[2m"}.get(
                f.severity, ""
            )
            print(f"  [{sev_colour}{f.severity}\033[0m] {f.kind}: {f.detail}")
    if result.scan_result:
        sr = result.scan_result
        print("\nText-scan result on extracted/scrubbed content:")
        print(f"  Verdict:     {sr.verdict}")
        print(f"  Confidence:  {sr.confidence:.1%}")
        if sr.matched_rules:
            print(f"  Rules:       {', '.join(sr.matched_rules)}")
        if sr.attack_technique:
            print(f"  Technique:   {sr.attack_technique}")


def _cmd_scan_image(args: argparse.Namespace) -> int:
    from raucle_detect.multimodal import MultimodalScanner

    scanner = Scanner(mode=args.mode, rules_dir=args.rules_dir)
    mm = MultimodalScanner(scanner)
    try:
        result = mm.scan_image(args.path)
    except ImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (FileNotFoundError, OSError) as exc:
        print(f"Error reading image: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_multimodal_result(result, path=args.path)

    return {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}[result.combined_verdict]


def _cmd_scan_pdf(args: argparse.Namespace) -> int:
    from raucle_detect.multimodal import MultimodalScanner

    scanner = Scanner(mode=args.mode, rules_dir=args.rules_dir)
    mm = MultimodalScanner(scanner)
    try:
        result = mm.scan_pdf(args.path)
    except ImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (FileNotFoundError, OSError) as exc:
        print(f"Error reading PDF: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_multimodal_result(result, path=args.path)

    return {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}[result.combined_verdict]


def _cmd_scrub(args: argparse.Namespace) -> int:
    from raucle_detect.multimodal import strip_invisible_unicode

    if args.text:
        text = args.text
    elif args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    else:
        if sys.stdin.isatty():
            print("Reading from stdin (Ctrl+D to finish):", file=sys.stderr)
        text = sys.stdin.read()

    scrubbed, hidden = strip_invisible_unicode(text)
    out = {
        "original_length": len(text),
        "scrubbed_length": len(scrubbed),
        "hidden_codepoints": hidden,
        "scrubbed_text": scrubbed,
    }
    if args.format == "json":
        print(json.dumps(out, indent=2))
    else:
        if hidden:
            print(
                f"\033[91mFound {sum(int(h.split('×')[1].rstrip(')')) for h in hidden)} "
                f"invisible codepoint(s)\033[0m across {len(hidden)} kind(s):"
            )
            for h in hidden:
                print(f"  - {h}")
            print(f"\nOriginal length:  {len(text)} chars")
            print(f"Scrubbed length:  {len(scrubbed)} chars")
            print("\nScrubbed text:")
            print(scrubbed)
        else:
            print("\033[92mNo invisible Unicode found.\033[0m")
    return 2 if hidden else 0


def _cmd_feed_keygen(args: argparse.Namespace) -> int:
    from raucle_detect.feed import IOCSigner

    signer = IOCSigner.generate(issuer=args.issuer)
    Path(f"{args.out}.key.pem").write_bytes(_dump_priv_pem(signer))
    Path(f"{args.out}.pub.pem").write_text(signer.public_key_pem)
    print(f"Issuer:   {args.issuer}")
    print(f"Key ID:   {signer.key_id}")
    print(f"Private:  {args.out}.key.pem  (keep secret)")
    print(f"Public:   {args.out}.pub.pem  (distribute to consumers)")
    return 0


def _dump_priv_pem(signer: object) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return signer._priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cmd_feed_sign(args: argparse.Namespace) -> int:
    import json as _json

    from raucle_detect.feed import IOCSigner

    drafts = _json.loads(Path(args.drafts).read_text())
    if not isinstance(drafts, list):
        print("error: drafts file must contain a JSON list", file=sys.stderr)
        return 1
    signer = IOCSigner.load_private_key(issuer=args.issuer, path=args.key)
    iocs = [
        signer.sign_ioc(
            kind=d["kind"],
            pattern=d["pattern"],
            severity=d.get("severity", "medium"),
            categories=d.get("categories", []),
            description=d.get("description", ""),
            revokes=d.get("revokes", []),
            expires_at=d.get("expires_at"),
        )
        for d in drafts
    ]
    feed = signer.build_feed(iocs, feed_id=args.feed_id)
    feed.save(args.out)
    print(f"Signed {len(iocs)} IOC(s) → {args.out}")
    print(f"Merkle root: {feed.merkle_root}")
    return 0


def _cmd_feed_verify(args: argparse.Namespace) -> int:
    from raucle_detect.feed import Feed

    feed = Feed.load(args.feed)
    pubkey = Path(args.pubkey).read_text() if args.pubkey else None
    try:
        feed.verify(pubkey_pem=pubkey)
    except ValueError as exc:
        print(f"\033[91mINVALID\033[0m: {exc}", file=sys.stderr)
        return 2
    print(f"\033[92mOK\033[0m  feed={feed.feed_id}  issuer={feed.issuer}  iocs={len(feed.iocs)}")
    print(f"    merkle_root={feed.merkle_root}")
    return 0


def _cmd_feed_pull(args: argparse.Namespace) -> int:
    from raucle_detect.feed import FeedStore, fetch_feed

    pubkey = Path(args.pubkey).read_text()
    feed = fetch_feed(args.url)
    store = FeedStore.open(args.store)
    try:
        store.merge(feed, pubkey_pem=pubkey)
    except ValueError as exc:
        print(f"\033[91mREJECTED\033[0m: {exc}", file=sys.stderr)
        return 2
    print(f"\033[92mMerged\033[0m  feed={feed.feed_id}  iocs={len(feed.iocs)}  → {args.store}")
    return 0


def _cmd_feed_list(args: argparse.Namespace) -> int:
    from raucle_detect.feed import FeedStore

    store = FeedStore.open(args.store)
    iocs = store.all_iocs()
    if not iocs:
        print("(empty)")
        return 0
    for ioc in iocs:
        print(f"{ioc.severity:8s} {ioc.kind:18s} {ioc.issuer:24s} {ioc.pattern[:60]}")
    print(f"\nTotal: {len(iocs)} live IOC(s) across {len(store.list_feeds())} feed(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "scan-image":
        return _cmd_scan_image(args)
    elif args.command == "scan-pdf":
        return _cmd_scan_pdf(args)
    elif args.command == "scrub":
        return _cmd_scrub(args)
    elif args.command == "serve":
        return _cmd_serve(args)
    elif args.command == "rules" and args.rules_command == "list":
        return _cmd_rules(args)
    elif args.command == "rules" and args.rules_command == "fuzz":
        return _cmd_rules_fuzz(args)
    elif args.command == "audit" and args.audit_command == "verify":
        return _cmd_audit_verify(args)
    elif args.command == "audit" and args.audit_command == "keygen":
        return _cmd_audit_keygen(args)
    elif args.command == "verify-receipt":
        return _cmd_verify_receipt(args)
    elif args.command == "mcp" and args.mcp_command == "serve":
        return _cmd_mcp_serve(args)
    elif args.command == "mcp" and args.mcp_command == "scan":
        return _cmd_mcp_scan(args)
    elif args.command == "provenance" and args.provenance_command == "keygen":
        return _cmd_provenance_keygen(args)
    elif args.command == "provenance" and args.provenance_command == "verify":
        return _cmd_provenance_verify(args)
    elif args.command == "provenance" and args.provenance_command == "trace":
        return _cmd_provenance_trace(args)
    elif args.command == "provenance" and args.provenance_command == "graph":
        return _cmd_provenance_graph(args)
    elif args.command == "provenance" and args.provenance_command == "replay":
        return _cmd_provenance_replay(args)
    elif args.command == "feed" and args.feed_command == "keygen":
        return _cmd_feed_keygen(args)
    elif args.command == "feed" and args.feed_command == "sign":
        return _cmd_feed_sign(args)
    elif args.command == "feed" and args.feed_command == "verify":
        return _cmd_feed_verify(args)
    elif args.command == "feed" and args.feed_command == "pull":
        return _cmd_feed_pull(args)
    elif args.command == "feed" and args.feed_command == "list":
        return _cmd_feed_list(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
