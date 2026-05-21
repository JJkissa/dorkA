#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          OSINT DORKING TOOL v2.1 — by dork_tool.py           ║
║  Automated open-source intelligence via search engine dorks  ║
║                                                              ║
║  Engine  : DuckDuckGo (free, no API key required)            ║
║  Output  : Standalone HTML report with analysis              ║
║  LLM     : OpenAPI Compatible local LLM integration          ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import time
import os
import json
import re
import html as html_lib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib

# ─────────────────────────────────────────────────────────────
# AUTO-INSTALL REQUIRED PACKAGES
# ─────────────────────────────────────────────────────────────

def _ensure_packages():
    """Install missing packages at startup so the script is self-contained."""
    import subprocess
    required = {"ddgs": "ddgs", "requests": "requests"}
    for pip_name, import_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            print(f"[*] Installing {pip_name}...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name, "--break-system-packages", "-q"],
                check=True
            )

_ensure_packages()

from ddgs import DDGS  # type: ignore
import requests  # type: ignore

# ─────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────

@dataclass
class SearchTarget:
    """Holds all known facts about the OSINT target."""
    full_name: str
    aliases: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    socials: Dict[str, str] = field(default_factory=dict)
    organization: str = ""
    location: str = ""
    target_type: str = "person"

@dataclass
class DorkResult:
    """A single search result collected during dorking."""
    query: str
    category: str
    subcategory: str
    title: str
    url: str
    snippet: str
    analysis: str = ""
    risk_level: str = "info"
    url_hash: str = ""

    def __post_init__(self):
        self.url_hash = hashlib.md5(self.url.encode()).hexdigest()

# ─────────────────────────────────────────────────────────────
# LLM INTEGRATION ARCHITECTURE
# ─────────────────────────────────────────────────────────────

class LLMClient:
    """Handles communication with a local OpenAPI compatible LLM (e.g. LM Studio, Ollama)."""
    def __init__(self, api_base: str, model_name: str):
        self.api_base = api_base.rstrip("/")
        self.model_name = model_name
        self.headers = {"Content-Type": "application/json"}

    def _chat_completion(self, system_prompt: str, user_prompt: str, temperature: float = 0.3) -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature
        }
        try:
            response = requests.post(
                f"{self.api_base}/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=90
            )
            response.raise_for_status()
            return response.json()['choices'][0]['message']['content'].strip()
        except requests.exceptions.RequestException as e:
            print(f" [!] LLM Communication Error: {e}")
            return ""

    def generate_dorks(self, target: SearchTarget, max_minutes: int) -> List[Tuple[str, str, str]]:
        """Generates dynamic queries based on the target profile using a time budget."""
        start_time = time.time()
        timeout_seconds = max_minutes * 60
        generated_queries = []
        
        print(f"\n[*] Prompting LLM for contextual dorks (Max time: {max_minutes} min)...")
        
        system_prompt = (
            "You are an expert OSINT investigator. Your task is to generate highly specific "
            "DuckDuckGo search queries (dorks) to find sensitive, hidden, or relevant information "
            "about the provided target. Output ONLY a raw JSON list of objects. Each object must have "
            "'query' (the search string), 'category' (string), and 'subcategory' (string)."
        )
        
        target_context = (
            f"Name: {target.full_name}\n"
            f"Aliases: {', '.join(target.aliases)}\n"
            f"Location: {target.location}\n"
            f"Organization: {target.organization}\n"
            f"Socials: {json.dumps(target.socials)}\n\n"
            "Generate 15 highly targeted queries. Use operators like site:, intext:, intitle:, ext:."
        )

        attempts = 0
        while (time.time() - start_time) < timeout_seconds and len(generated_queries) < 15:
            attempts += 1
            print(f"    -> LLM Generation Attempt {attempts}...")
            response = self._chat_completion(system_prompt, target_context, temperature=0.7)
            
            if not response:
                time.sleep(2)
                continue
                
            try:
                # Extract JSON block in case the LLM wrapped it in markdown
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
                raw_json = json_match.group(0) if json_match else response
                
                parsed_dorks = json.loads(raw_json)
                for d in parsed_dorks:
                    if 'query' in d:
                        generated_queries.append((
                            d['query'], 
                            d.get('category', 'LLM Generated'), 
                            d.get('subcategory', 'Dynamic')
                        ))
                break  # Successful generation, exit loop
            except json.JSONDecodeError:
                print("    [!] Failed to parse LLM JSON response. Retrying...")
                
        # Save generated queries for later usage
        if generated_queries:
            filename = f"llm_dorks_{target.full_name.replace(' ', '_')}_{int(time.time())}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([{'query': q, 'category': c, 'subcategory': s} for q, c, s in generated_queries], f, indent=4)
            print(f"[*] Successfully generated {len(generated_queries)} queries via LLM. Saved to {filename}")

        return generated_queries

    def validate_result(self, target: SearchTarget, result: DorkResult) -> bool:
        """Strictly verifies if the search result contextually matches the target."""
        system_prompt = (
            "You are a strict data validation agent. You analyze search engine results and determine "
            "if they genuinely pertain to the specific target profile. Answer ONLY with 'YES' or 'NO'."
        )
        
        validation_prompt = (
            f"Target Profile:\n"
            f"Name: {target.full_name}, Location: {target.location}, Organization: {target.organization}\n\n"
            f"Search Result:\n"
            f"Title: {result.title}\n"
            f"Snippet: {result.snippet}\n"
            f"URL: {result.url}\n\n"
            f"Is this search result genuinely about the Target Profile? (e.g., if the target is from "
            f"Finland, and this is a random match in an unrelated document, say NO). Answer YES or NO:"
        )
        
        reply = self._chat_completion(system_prompt, validation_prompt, temperature=0.1).strip().upper()
        return "YES" in reply

# ─────────────────────────────────────────────────────────────
# DORK DATABASE
# ─────────────────────────────────────────────────────────────

DORK_DATABASE: Dict[str, Dict] = {
    "documents": {
        "label": "Documents", "icon": "📄", "risk": "medium", "description": "Publicly indexed files",
        "templates": [('"{name}" filetype:pdf', "PDF"), ('"{name}" filetype:xls OR filetype:xlsx', "Spreadsheet")]
    },
    "social_media": {
        "label": "Social Media", "icon": "🌐", "risk": "low", "description": "Public profiles",
        "templates": [('site:linkedin.com "{name}"', "LinkedIn"), ('site:twitter.com "{name}"', "Twitter")]
    },
    "data_breaches": {
        "label": "Breach & Leaks", "icon": "🔓", "risk": "high", "description": "Credential leaks",
        "templates": [('"{name}" site:pastebin.com', "Pastebin"), ('"{name}" "dump" filetype:txt', "Text Dump")]
    }
}

RISK_META = {
    "info":     {"color": "#6c757d", "badge": "#6c757d", "label": "INFO",     "emoji": "ℹ️"},
    "low":      {"color": "#0d6efd", "badge": "#0d6efd", "label": "LOW",      "emoji": "🔵"},
    "medium":   {"color": "#fd7e14", "badge": "#fd7e14", "label": "MEDIUM",   "emoji": "🟠"},
    "high":     {"color": "#dc3545", "badge": "#dc3545", "label": "HIGH",     "emoji": "🔴"},
    "critical": {"color": "#9b0000", "badge": "#ff0000", "label": "CRITICAL", "emoji": "🚨"},
}

def build_queries(target: SearchTarget, selected_categories: Optional[List[str]] = None) -> List[Tuple[str, str, str]]:
    queries: List[Tuple[str, str, str]] = []
    name_variants = [target.full_name] + target.aliases[:4]
    
    def expand(template: str, name: str) -> str:
        return template.replace("{name}", f'"{name}"')

    for cat_key, cat_data in DORK_DATABASE.items():
        if selected_categories and cat_key not in selected_categories:
            continue
        for template, subcat in cat_data["templates"]:
            for name in name_variants:
                queries.append((expand(template, name), cat_key, subcat))
    return list(set(queries))

def analyze_result(raw: Dict, target: SearchTarget, category: str) -> Tuple[str, str]:
    s = str(raw).lower()
    risk = DORK_DATABASE.get(category, {}).get("risk", "info")
    notes = []

    def escalate(r: str):
        nonlocal risk
        levels = list(RISK_META.keys())
        if levels.index(r) > levels.index(risk):
            risk = r

    if "password" in s or "passwd" in s:
        escalate("critical")
        notes.append("🔑 Credential: Password/credential data present.")
    
    return " ".join(notes) if notes else "Relevant result found.", risk

def execute_dork(query: str, max_results: int = 5, delay: float = 2.0) -> List[Dict]:
    for attempt in range(3):
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
            time.sleep(delay + attempt * 0.5)
            return results
        except Exception as exc:
            wait = delay * (2 ** attempt)
            print(f" [!] Query error (attempt {attempt+1}/3): {exc} — waiting {wait:.1f}s")
            time.sleep(wait)
    return []

def run_all_dorks(
    target: SearchTarget,
    queries: List[Tuple[str, str, str]],
    max_per_query: int = 5,
    delay: float = 2.0,
    max_total_queries: Optional[int] = None,
    llm_client: Optional[LLMClient] = None,
) -> List[DorkResult]:
    
    results: List[DorkResult] = []
    seen_urls: set = set()
    total = min(len(queries), max_total_queries) if max_total_queries else len(queries)
    
    print(f"\n[*] Executing {total} dork queries...")
    for idx, (query_str, cat, subcat) in enumerate(queries[:total], 1):
        print(f"  [{idx}/{total}] {query_str}")
        raw_results = execute_dork(query_str, max_results=max_per_query, delay=delay)
        
        for raw in raw_results:
            url = raw.get("href", "")
            if not url or url in seen_urls:
                continue
                
            analysis, risk = analyze_result(raw, target, cat)
            
            dork_res = DorkResult(
                query=query_str,
                category=cat,
                subcategory=subcat,
                title=raw.get("title", "No Title"),
                url=url,
                snippet=raw.get("body", ""),
                analysis=analysis,
                risk_level=risk
            )

            if llm_client:
                is_relevant = llm_client.validate_result(target, dork_res)
                if not is_relevant:
                    print(f"      [-] LLM discarded irrelevant result: {dork_res.title[:50]}...")
                    continue 
                else:
                    print(f"      [+] LLM confirmed relevance: {dork_res.url}")

            seen_urls.add(url)
            results.append(dork_res)
            
    return results

def generate_html_report(target: SearchTarget, results: List[DorkResult], output_path: str, duration_seconds: float, queries_run: int) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>OSINT Report — {html_lib.escape(target.full_name)}</title></head>
    <body style="font-family: sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem;">
        <h1>🕵️ OSINT Report: {html_lib.escape(target.full_name)}</h1>
        <p>Generated: {now_str} | Queries: {queries_run} | Valid Results: {len(results)} | Duration: {duration_seconds:.1f}s</p>
        <hr style="border: 1px solid #30363d;">
    """
    for res in results:
        html += f"""
        <div style="border: 1px solid #30363d; margin-bottom: 1rem; padding: 1rem; border-radius: 8px;">
            <h3><a href="{res.url}" style="color: #58a6ff;">{html_lib.escape(res.title)}</a></h3>
            <p style="color: #8b949e; font-size: 0.9em;">{html_lib.escape(res.snippet)}</p>
            <p><strong>Category:</strong> {res.category} ({res.subcategory}) | <strong>Risk:</strong> {res.risk_level}</p>
        </div>
        """
    html += "</body></html>"
    Path(output_path).write_text(html, encoding="utf-8")
    return output_path

# ─────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Automated OSINT Dorking Tool with LLM Integration")
    parser.add_argument("--target", required=True, help="Target full name or company")
    parser.add_argument("--aliases", default="", help="Comma-separated aliases")
    parser.add_argument("--usernames", default="", help="Comma-separated usernames")
    parser.add_argument("--socials", default="", help="Comma-separated socials (e.g. twitter:handle)")
    parser.add_argument("--org", default="", help="Associated organisation")
    parser.add_argument("--location", default="", help="Target location")
    parser.add_argument("--categories", default="", help="Comma-separated categories to run")
    parser.add_argument("--max-per-query", type=int, default=5, help="Max results per query")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between queries")
    parser.add_argument("--max-total", type=int, default=0, help="Max queries to run in total")
    parser.add_argument("--output", default="", help="Custom output HTML path")
    
    # LLM Settings
    llm_group = parser.add_argument_group("LLM Integration")
    llm_group.add_argument("--llm-url", type=str, default="http://localhost:1234/v1", help="Base URL for the OpenAPI local LLM")
    llm_group.add_argument("--llm-model", type=str, default="llama-3.2", help="Model identifier")
    llm_group.add_argument("--llm-gen-timeout", type=int, default=10, help="Max time (minutes) to generate queries")
    llm_group.add_argument("--disable-llm", action="store_true", help="Disable LLM generation and validation entirely")
    
    return parser.parse_args()

def main():
    args = parse_args()
    
    target = SearchTarget(
        full_name=args.target.strip(),
        aliases=[a.strip() for a in args.aliases.split(",") if a.strip()],
        usernames=[u.strip() for u in args.usernames.split(",") if u.strip()],
        socials={p.split(":")[0].strip(): p.split(":")[1].strip() for p in args.socials.split(",") if ":" in p},
        organization=args.org.strip(),
        location=args.location.strip()
    )

    print(f"\n[*] Target: {target.full_name} ({target.location})")
    
    # Initialize LLM Client
    llm_client = None
    if getattr(args, 'disable_llm', False) is False:
        llm_client = LLMClient(api_base=args.llm_url, model_name=args.llm_model)

    queries = []
    
    # Generate LLM specific queries based on target
    if llm_client:
        queries.extend(llm_client.generate_dorks(target, max_minutes=args.llm_gen_timeout))
        
    # Append fallback static database queries
    queries.extend(build_queries(target, args.categories.split(",") if args.categories else None))

    if not queries:
        print("[!] No queries generated. Exiting.")
        sys.exit(1)

    print(f"[*] Total queries configured: {len(queries)}")
    
    t_start = time.time()
    results = run_all_dorks(
        target,
        queries,
        max_per_query=args.max_per_query,
        delay=args.delay,
        max_total_queries=args.max_total if args.max_total > 0 else None,
        llm_client=llm_client
    )
    duration = time.time() - t_start

    out_path = args.output or f"osint_{target.full_name.replace(' ', '_').lower()}_{int(time.time())}.html"
    generate_html_report(target, results, out_path, duration, len(queries))
    print(f"\n[*] Finished. Valid Results: {len(results)}. Report saved to {out_path}")

if __name__ == "__main__":
    main()