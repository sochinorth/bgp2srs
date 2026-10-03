#!/usr/bin/env python3
# DISCLOSURE: one-shot vibecoded with DeepSeek, don't @ me

from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger("bgp2srs")

DEFAULT_TABLE_URL = "https://bgp.tools/table.jsonl"
DEFAULT_USER_AGENT = "bgp2srs/0.1 (+https://github.com/sochinorth/bgp2srs)"

RULESET_FORMAT_VERSION = 3
SHARD_SIZE = 1000


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #
def download_table(
    url: str,
    dest: Path,
    *,
    api_key: str | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: int = 900,
    retries: int = 3,
) -> None:
    """Stream `url` into `dest`, retrying a few times on transient errors."""
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/x-ndjson, application/json, text/plain, */*",
    }
    if api_key:
        # bgp.tools accepts the API key in a header named after the service.
        headers["bgp.tools"] = api_key

    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        LOG.info("downloading %s (attempt %d/%d)", url, attempt, retries)
        started = time.monotonic()
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                with dest.open("wb") as fh:
                    shutil.copyfileobj(response, fh, length=1 << 20)
            size = dest.stat().st_size
            if size == 0:
                raise RuntimeError("received an empty response")
            LOG.info(
                "downloaded %.1f MiB in %.1fs",
                size / 1048576,
                time.monotonic() - started,
            )
            return
        except Exception as exc:  # noqa: BLE001 - we want to retry everything
            last_error = exc
            LOG.warning("download failed: %s", exc)
            if attempt < retries:
                time.sleep(5 * attempt)

    raise SystemExit(f"could not download {url}: {last_error}")


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def parse_table(path: Path) -> dict[int, set[ipaddress._BaseNetwork]]:
    """Return {asn: {network, ...}} from a bgp.tools JSONL dump."""
    by_asn: dict[int, set[ipaddress._BaseNetwork]] = defaultdict(set)
    total = 0
    skipped = 0

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                record = json.loads(line)
                network = ipaddress.ip_network(record["CIDR"], strict=False)
                asn = int(record["ASN"])
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                skipped += 1
                if len(skipped_samples) < 3:
                    skipped_samples.append(line[:200])
                continue

            if asn > 0:
                by_asn[asn].add(network)

    if skipped:
        LOG.warning("skipped %d unparseable lines", skipped)
    LOG.info(
        "parsed %d lines -> %d unique prefixes across %d origin ASes",
        total,
        sum(len(v) for v in by_asn.values()),
        len(by_asn),
    )
    return by_asn


def _network_sort_key(net: ipaddress._BaseNetwork) -> tuple[int, int, int]:
    return (net.version, int(net.network_address), net.prefixlen)


# --------------------------------------------------------------------------- #
# Rule-set generation
# --------------------------------------------------------------------------- #
def write_source_ruleset(networks: set[ipaddress._BaseNetwork], dest: Path) -> int:
    """Write a sing-box source rule-set (JSON) and return the CIDR count."""
    cidrs = [str(net) for net in sorted(networks, key=_network_sort_key)]
    document = {
        "version": RULESET_FORMAT_VERSION,
        "rules": [{"ip_cidr": cidrs}],
    }
    dest.write_text(
        json.dumps(document, separators=(",", ":")),
        encoding="utf-8",
    )
    return len(cidrs)


def compile_ruleset(binary: str, source: Path, destination: Path) -> None:
    """Compile a JSON source rule-set into the binary .srs format."""
    proc = subprocess.run(
        [binary, "rule-set", "compile", str(source), "-o", str(destination)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(message or f"sing-box exited with {proc.returncode}")


def check_sing_box(binary: str) -> str:
    try:
        proc = subprocess.run(
            [binary, "version"], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        raise SystemExit(
            f"sing-box binary not found: {binary!r}. "
            "Install it or pass --sing-box /path/to/sing-box"
        )
    if proc.returncode != 0:
        raise SystemExit(f"`{binary} version` failed: {proc.stderr.strip()}")
    version = (proc.stdout or "").strip().splitlines()
    version_line = version[0] if version else "unknown"
    LOG.info("using %s (%s)", binary, version_line)
    return version_line


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build per-AS sing-box .srs rule-sets from bgp.tools.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--table-url",
        default=os.environ.get("BGP_TABLE_URL", DEFAULT_TABLE_URL),
        help="URL of the bgp.tools JSONL table",
    )
    parser.add_argument(
        "--table-file",
        type=Path,
        help="use an already downloaded table instead of fetching it",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("dist"),
        help="where the compiled .srs files are written",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="where intermediate JSON files go (default: a temp directory)",
    )
    parser.add_argument(
        "--keep-json",
        action="store_true",
        help="also keep the uncompiled JSON rule-sets next to the .srs files",
    )
    parser.add_argument(
        "--sing-box",
        default=os.environ.get("SING_BOX", "sing-box"),
        help="path to the sing-box binary",
    )
    parser.add_argument(
        "--min-prefixes",
        type=int,
        default=1,
        help="skip ASes announcing fewer than this many prefixes",
    )
    parser.add_argument(
        "--max-asn",
        type=int,
        default=0,
        help="only build the N largest ASes (0 = all of them)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(8, os.cpu_count() or 2),
        help="parallel sing-box compile jobs",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("BGP_TOOLS_API_KEY"),
        help="bgp.tools API key (or set BGP_TOOLS_API_KEY)",
    )
    parser.add_argument(
        "--user-agent",
        default=os.environ.get("BGP_USER_AGENT", DEFAULT_USER_AGENT),
        help="User-Agent sent to bgp.tools",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    out_dir: Path = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp_ctx: tempfile.TemporaryDirectory | None = None
    if args.work_dir:
        work_dir = args.work_dir.resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        tmp_ctx = tempfile.TemporaryDirectory(prefix="bgp2srs-")
        work_dir = Path(tmp_ctx.name)

    try:
        # -- 1. obtain the table ------------------------------------------- #
        if args.table_file:
            table_path = args.table_file.resolve()
            if not table_path.is_file():
                raise SystemExit(f"table file not found: {table_path}")
            LOG.info("using existing table %s", table_path)
        else:
            table_path = work_dir / "table.jsonl"
            download_table(
                args.table_url,
                table_path,
                api_key=args.api_key,
                user_agent=args.user_agent,
            )

        # -- 2. group by origin AS ------------------------------------------ #
        by_asn = parse_table(table_path)

        selected = [
            (asn, networks)
            for asn, networks in by_asn.items()
            if len(networks) >= args.min_prefixes
        ]
        if args.max_asn > 0:
            selected.sort(key=lambda item: len(item[1]), reverse=True)
            selected = selected[: args.max_asn]

        if not selected:
            raise SystemExit("no ASes matched the given filters")

        total_prefixes = sum(len(n) for _, n in selected)
        LOG.info(
            "building %d rule-sets (%d prefixes) with %d workers",
            len(selected),
            total_prefixes,
            args.workers,
        )

        # -- 3. write the JSON source rule-sets ----------------------------- #
        src_dir = work_dir / "src"
        if src_dir.exists():
            shutil.rmtree(src_dir)
        src_dir.mkdir(parents=True)

        jobs: list[tuple[int, Path, Path, int]] = []
        for asn, networks in sorted(selected):
            shard_dir = out_dir / f"{asn // 1000}000"
            shard_dir.mkdir(parents=True, exist_ok=True)

            source = src_dir / f"as{asn}.json"
            destination = shard_dir / f"as{asn}.srs"
            count = write_source_ruleset(networks, source)
            jobs.append((asn, source, destination, count))

        # -- 4. compile to .srs --------------------------------------------- #
        check_sing_box(args.sing_box)

        failures: list[tuple[int, str]] = []
        completed = 0
        started = time.monotonic()

        with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
            future_map = {
                pool.submit(compile_ruleset, args.sing_box, src, dst): (asn, dst)
                for asn, src, dst, _ in jobs
            }
            for future in cf.as_completed(future_map):
                asn, dst = future_map[future]
                completed += 1
                try:
                    future.result()
                except Exception as exc:  # noqa: BLE001
                    failures.append((asn, str(exc)))
                    LOG.error("AS%d failed to compile: %s", asn, exc)
                    dst.unlink(missing_ok=True)
                if completed % 1000 == 0 or completed == len(jobs):
                    LOG.info("compiled %d/%d rule-sets", completed, len(jobs))

        LOG.info(
            "compiled %d rule-sets in %.1fs (%d failures)",
            len(jobs) - len(failures),
            time.monotonic() - started,
            len(failures),
        )

        # -- 5. housekeeping + manifest -------------------------------------- #
        produced = {dst.name for _, _, dst, _ in jobs if dst.exists()}
        for stale in out_dir.rglob("*.srs"):
            if stale.name not in produced:
                LOG.debug("removing stale %s", stale.name)
                stale.unlink()

        if args.keep_json:
            for _, src, _, _ in jobs:
                shutil.copy2(src, out_dir / src.name)

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": args.table_url if not args.table_file else str(args.table_file),
            "sing_box": check_sing_box(args.sing_box),
            "min_prefixes": args.min_prefixes,
            "asn_count": len(produced),
            "prefix_count": sum(c for _, _, dst, c in jobs if dst.exists()),
            "rulesets": {
                str(asn): {
                    "file": dst.relative_to(out_dir).as_posix(),
                    "prefixes": count
                }
                for asn, _, dst, count in jobs
                if dst.exists()
            },
        }
        (out_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        if failures:
            LOG.warning("%d ASes could not be compiled", len(failures))
            return 1
        return 0

    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    sys.exit(main())