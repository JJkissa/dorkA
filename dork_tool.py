#!/usr/bin/env python3
import argparse
import json
import sys
import time
from typing import Dict, Iterable, List

try:
    from duckduckgo_search import DDGS  # type: ignore
    _DDGS_IMPORT_ERROR = None
except (ImportError, ModuleNotFoundError) as exc:
    DDGS = None
    _DDGS_IMPORT_ERROR = exc

CATEGORY_QUERIES = {
    "social_media": [
        '"{target}" site:twitter.com',
        '"{target}" site:linkedin.com',
        '"{target}" site:facebook.com',
        '"{target}" site:instagram.com',
    ],
    "email_phone": [
        '"{target}" ("@" OR "email" OR "phone" OR "contact")',
        '"{target}" "@gmail.com" OR "@outlook.com" OR "@yahoo.com"',
    ],
    "data_breaches": [
        '"{target}" ("leak" OR "breach" OR "paste")',
        '"{target}" site:pastebin.com',
    ],
    "documents": [
        '"{target}" (filetype:pdf OR filetype:doc OR filetype:xls)',
    ],
    "code": [
        '"{target}" site:github.com',
        '"{target}" site:gitlab.com',
    ],
}


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_socials(value: str) -> Dict[str, str]:
    socials: Dict[str, str] = {}
    for entry in _split_csv(value):
        if ":" not in entry:
            raise argparse.ArgumentTypeError(f"Invalid social entry '{entry}'. Use platform:handle")
        platform, handle = entry.split(":", 1)
        platform = platform.strip()
        handle = handle.strip()
        if not platform or not handle:
            raise argparse.ArgumentTypeError(f"Invalid social entry '{entry}'. Use platform:handle")
        socials[platform] = handle
    return socials


def _build_context_phrases(args: argparse.Namespace) -> List[str]:
    phrases = [args.target]
    phrases.extend(args.aliases)
    phrases.extend(args.usernames)
    phrases.extend(f"{platform} {handle}" for platform, handle in args.socials.items())
    if args.org:
        phrases.append(args.org)
    if args.location:
        phrases.append(args.location)
    return [p for p in dict.fromkeys(phrases) if p]


def _build_queries(args: argparse.Namespace) -> List[str]:
    phrases = _build_context_phrases(args)
    queries: List[str] = []
    for category in args.categories:
        templates = CATEGORY_QUERIES[category]
        for phrase in phrases:
            for template in templates:
                queries.append(template.format(target=phrase))
    return queries[: args.max_total]


def _validate_categories(value: str) -> List[str]:
    categories = _split_csv(value)
    if not categories:
        raise argparse.ArgumentTypeError("At least one category must be provided")
    invalid = [c for c in categories if c not in CATEGORY_QUERIES]
    if invalid:
        choices = ", ".join(sorted(CATEGORY_QUERIES))
        invalid_str = ", ".join(invalid)
        raise argparse.ArgumentTypeError(f"Unknown categories: {invalid_str}. Valid categories: {choices}")
    return categories


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate and run Google dork style discovery queries.")
    parser.add_argument("--target", help="Person or organization target")
    parser.add_argument("--type", choices=["person", "organization"], default="person")
    parser.add_argument("--aliases", type=_split_csv, default=[])
    parser.add_argument("--usernames", type=_split_csv, default=[])
    parser.add_argument("--socials", type=_parse_socials, default={})
    parser.add_argument("--org", default="")
    parser.add_argument("--location", default="")
    parser.add_argument("--categories", type=_validate_categories, default=list(CATEGORY_QUERIES))
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--max-total", type=int, default=100)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list-categories", action="store_true")

    args = parser.parse_args(list(argv))

    if args.list_categories:
        return args

    if not args.target:
        parser.error("--target is required unless --list-categories is used")

    if args.max_total <= 0:
        parser.error("--max-total must be greater than 0")

    if args.delay < 0:
        parser.error("--delay must be 0 or greater")

    return args


def _run_queries(queries: List[str], delay: float) -> List[dict]:
    if DDGS is None:
        details = f" ({_DDGS_IMPORT_ERROR})" if _DDGS_IMPORT_ERROR else ""
        raise RuntimeError(f"duckduckgo-search could not be imported{details}. Run: pip install duckduckgo-search")

    results: List[dict] = []
    with DDGS() as ddgs:  # type: ignore[misc]
        for query in queries:
            found = list(ddgs.text(query, max_results=5))
            results.append({"query": query, "results": found})
            if delay:
                time.sleep(delay)
    return results


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    if args.list_categories:
        for category in sorted(CATEGORY_QUERIES):
            print(category)
        return 0

    if args.type == "organization" and not args.org:
        args.org = args.target

    queries = _build_queries(args)

    if args.dry_run:
        for query in queries:
            print(query)
        return 0

    payload = {
        "target": args.target,
        "type": args.type,
        "query_count": len(queries),
        "results": _run_queries(queries, args.delay),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
