"""Admin CLI for pwncorpus.

  python -m pwncorpus.cli init --db corpus.db
  python -m pwncorpus.cli token --db corpus.db --label ingestor --scopes ingest
  python -m pwncorpus.cli ingest --db corpus.db --source breach-2026Q3 --file leaks.txt
  python -m pwncorpus.cli build --db corpus.db --k 50
  python -m pwncorpus.cli refresh --db corpus.db --version 3
  python -m pwncorpus.cli activate --db corpus.db --version 3
  python -m pwncorpus.cli retract --db corpus.db --batch <id>
  python -m pwncorpus.cli export --db corpus.db --version 3 --out export-v3/
  python -m pwncorpus.cli serve --db corpus.db --host 127.0.0.1 --port 8080
"""
from __future__ import annotations

import argparse
import json
import sys

from . import core, db


def _conn(args):
    return db.connect(args.db)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pwncorpus")
    ap.add_argument("--db", default="corpus.db", help="SQLite database path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database schema")

    p = sub.add_parser("token", help="create an API token (shown once)")
    p.add_argument("--label", required=True)
    p.add_argument("--scopes", required=True,
                   help="comma separated: ingest,retract,publish")

    p = sub.add_parser("ingest", help="ingest a batch file (one password or "
                       "'sha1:<hex>' per line)")
    p.add_argument("--source", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--idempotency-key", default=None)

    p = sub.add_parser("build", help="build a candidate publication")
    p.add_argument("--k", type=int, default=core.DEFAULT_THRESHOLD_K,
                   help="minimum bucket set size")

    p = sub.add_parser("activate", help="atomically activate a candidate "
                       "(fails with a conflict if the candidate is stale)")
    p.add_argument("--version", type=int, required=True)

    p = sub.add_parser("refresh", help="rebuild a stale candidate from current "
                       "source data, keeping its version and threshold k")
    p.add_argument("--version", type=int, required=True)

    p = sub.add_parser("retract", help="retract a batch (effective next build)")
    p.add_argument("--batch", required=True)

    p = sub.add_parser("correct", help="exclude fingerprints of a batch "
                       "(false positives), effective next build")
    p.add_argument("--batch", required=True)
    p.add_argument("--file", required=True,
                   help="file with one password or 'sha1:<hex>' per line")

    p = sub.add_parser("export", help="export a version for offline verification")
    p.add_argument("--version", type=int, required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("status", help="show publications and batch stats")

    p = sub.add_parser("serve", help="run the HTTP server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)

    args = ap.parse_args(argv)

    if args.cmd == "init":
        db.init(args.db)
        print(f"initialised {args.db}")
        return 0

    if args.cmd == "serve":
        from .server import make_server
        srv = make_server(args.db, args.host, args.port)
        print(f"serving on http://{args.host}:{args.port}  (db={args.db})")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    conn = _conn(args)
    try:
        if args.cmd == "token":
            token = core.create_token(conn, args.label, args.scopes.split(","))
            print(f"token (store it now, it is not recoverable): {token}")
            return 0

        if args.cmd == "ingest":
            items = []
            with open(args.file, "r", encoding="utf-8", errors="surrogateescape") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    if line.lower().startswith("sha1:"):
                        items.append({"sha1": line[5:]})
                    else:
                        items.append(line)
            result = core.ingest_batch(conn, args.source, items,
                                       args.idempotency_key)
            items.clear()
            print(json.dumps(result, indent=2))
            return 0

        if args.cmd == "build":
            print(json.dumps(core.build_candidate(conn, args.k), indent=2))
            return 0

        if args.cmd == "activate":
            print(json.dumps(core.activate(conn, args.version), indent=2))
            return 0

        if args.cmd == "refresh":
            print(json.dumps(core.refresh_candidate(conn, args.version), indent=2))
            return 0

        if args.cmd == "retract":
            print(json.dumps(core.retract_batch(conn, args.batch), indent=2))
            return 0

        if args.cmd == "correct":
            items = []
            with open(args.file, "r", encoding="utf-8", errors="surrogateescape") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    if line.lower().startswith("sha1:"):
                        items.append({"sha1": line[5:]})
                    else:
                        items.append(line)
            print(json.dumps(core.add_corrections(conn, args.batch, items), indent=2))
            return 0

        if args.cmd == "export":
            manifest = core.export_version(conn, args.version, args.out)
            print(f"exported v{args.version} to {args.out} "
                  f"({len(manifest['files'])} buckets, "
                  f"manifest {manifest['manifest_sha256'][:16]}...)")
            return 0

        if args.cmd == "status":
            state = core.review_state(conn)
            print(json.dumps({
                "active_version": core.current_version(conn),
                "corpus_state": state["corpus_state"],
                "publications": state["publications"],
                "stats": state["stats"],
            }, indent=2))
            return 0
    except core.CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
