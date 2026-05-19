#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          OSINT DORKING TOOL v2.0 — by dork_tool.py           ║
║  Automated open-source intelligence via search engine dorks  ║
║                                                              ║
║  Engine  : DuckDuckGo (free, no API key required)            ║
║  Output  : Standalone HTML report with analysis              ║
║                                                              ║
║  Usage:                                                      ║
║    python dork_tool.py --target "Jane Doe"                   ║
║      --aliases "janedoe,j.doe"                               ║
║      --usernames "janedoe99,janed"                           ║
║      --socials "twitter:janedoe,github:janedoe99"            ║
║      --org "Acme Corp"                                       ║
║      --location "New York"                                   ║
║      --type person                                           ║
║      --delay 2.0                                             ║
║      --max-per-query 5                                       ║
║      --categories social_media,documents,email_phone         ║
╚══════════════════════════════════════════════════════════════╝

Requirements:
    pip install ddgs requests

Notes:
    - DuckDuckGo supports: site:, filetype:/ext:, inurl:, intitle:, intext:, OR, "exact"
    - Google-only operators (cache:) are included for reference but may not work on DDG
    - Results are deduplicated by URL across all queries
    - Be respectful: use only for legitimate OSINT / research purposes
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
import requests  # type: ignore  # noqa: F401  (kept for future use)


# ─────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────

@dataclass
class SearchTarget:
    """Holds all known facts about the OSINT target."""
    full_name: str
    aliases: List[str] = field(default_factory=list)        # other real names / nicknames
    usernames: List[str] = field(default_factory=list)       # online handles
    socials: Dict[str, str] = field(default_factory=dict)    # {"platform": "handle"}
    organization: str = ""
    location: str = ""
    target_type: str = "person"                              # "person" | "organization"

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
    risk_level: str = "info"    # info | low | medium | high | critical
    url_hash: str = ""          # for deduplication

    def __post_init__(self):
        # Stable hash so we deduplicate across different queries that return the same URL
        self.url_hash = hashlib.md5(self.url.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────
# DORK DATABASE  — 250+ templates across 18 categories
# ─────────────────────────────────────────────────────────────
# Template placeholders:
#   {name}      → target's full name (or current alias in loop)
#   {username}  → current username in loop
#   {org}       → organisation name
#   {domain}    → guessed organisation domain
#   {email}     → guessed email from first.last pattern
#
# Risk levels: info | low | medium | high | critical

DORK_DATABASE: Dict[str, Dict] = {

    # ── Social media ──────────────────────────────────────────
    "social_media": {
        "label": "Social Media",
        "icon": "🌐",
        "risk": "low",
        "description": "Public profiles and activity across social platforms",
        "templates": [
            # LinkedIn
            ('site:linkedin.com "{name}"',                                "LinkedIn"),
            ('site:linkedin.com/in "{name}"',                             "LinkedIn Direct"),
            ('site:linkedin.com "{name}" "{org}"',                        "LinkedIn + Org"),
            # Twitter / X
            ('site:twitter.com "{name}"',                                 "Twitter"),
            ('site:x.com "{name}"',                                       "X (Twitter)"),
            ('"twitter.com/{username}"',                                  "Twitter Handle"),
            ('"x.com/{username}"',                                        "X Handle"),
            # Facebook
            ('site:facebook.com "{name}"',                                "Facebook"),
            ('"facebook.com/{username}"',                                 "Facebook Handle"),
            # Instagram
            ('site:instagram.com "{username}"',                           "Instagram"),
            ('"instagram.com/{username}"',                                "Instagram Handle"),
            ('"instagram.com" "{name}"',                                  "Instagram Name"),
            # Reddit
            ('site:reddit.com "u/{username}"',                            "Reddit User"),
            ('site:reddit.com "{name}"',                                  "Reddit Activity"),
            ('site:reddit.com/user "{username}"',                         "Reddit Profile"),
            # GitHub
            ('site:github.com "{username}"',                              "GitHub"),
            ('site:github.com "{name}"',                                  "GitHub Name"),
            # TikTok
            ('site:tiktok.com "@{username}"',                             "TikTok"),
            ('site:tiktok.com "{name}"',                                  "TikTok Name"),
            # YouTube
            ('site:youtube.com "{name}"',                                 "YouTube"),
            ('site:youtube.com/channel "{name}"',                        "YouTube Channel"),
            # Pinterest
            ('site:pinterest.com "{name}"',                               "Pinterest"),
            ('site:pinterest.com "{username}"',                           "Pinterest Handle"),
            # Telegram
            ('site:t.me "{username}"',                                    "Telegram"),
            ('"t.me/{username}"',                                         "Telegram Link"),
            # Snapchat
            ('site:snapchat.com/add "{username}"',                        "Snapchat"),
            # Mastodon / Fediverse
            ('"{name}" site:mastodon.social OR site:fosstodon.org',       "Mastodon"),
            # Tumblr
            ('site:tumblr.com "{name}"',                                  "Tumblr"),
            # Medium
            ('site:medium.com "@{username}"',                             "Medium"),
            ('site:medium.com "{name}"',                                  "Medium Name"),
            # Discord leaks / mentions
            ('"discord" "{name}" "{username}"',                           "Discord Mention"),
            # Twitch
            ('site:twitch.tv "{username}"',                               "Twitch"),
            # Steam
            ('site:steamcommunity.com "{username}"',                      "Steam"),
            # Flickr
            ('site:flickr.com/people "{username}"',                       "Flickr"),
            # VKontakte
            ('site:vk.com "{name}"',                                      "VKontakte"),
            # Weibo
            ('site:weibo.com "{name}"',                                   "Weibo"),
        ],
    },

    # ── Professional / business ───────────────────────────────
    "professional": {
        "label": "Professional",
        "icon": "💼",
        "risk": "info",
        "description": "Work history, executive roles, professional presence",
        "templates": [
            ('site:linkedin.com/in "{name}"',                             "LinkedIn Profile"),
            ('"{name}" site:crunchbase.com',                              "Crunchbase"),
            ('"{name}" site:angel.co OR site:wellfound.com',              "AngelList/Wellfound"),
            ('"{name}" "curriculum vitae" OR "resume" OR "CV" filetype:pdf', "CV/Resume PDF"),
            ('"{name}" "speaker" OR "keynote" site:eventbrite.com',       "Events Speaker"),
            ('"{name}" "CEO" OR "CTO" OR "COO" OR "founder" OR "director"',"Executive Role"),
            ('"{name}" site:glassdoor.com',                               "Glassdoor"),
            ('"{name}" site:indeed.com',                                  "Indeed"),
            ('"{name}" site:xing.com',                                    "XING"),
            ('"{name}" "patent" filetype:pdf OR site:patents.google.com', "Patents"),
            ('"{name}" "academic" OR "professor" OR "researcher" site:edu',"Academia"),
            ('"{name}" site:researchgate.net',                            "ResearchGate"),
            ('"{name}" site:academia.edu',                                "Academia.edu"),
            ('"{name}" "speaker" "conference" OR "summit"',               "Conference Speaker"),
        ],
    },

    # ── Documents ─────────────────────────────────────────────
    "documents": {
        "label": "Documents",
        "icon": "📄",
        "risk": "medium",
        "description": "Publicly indexed files associated with the target",
        "templates": [
            ('"{name}" filetype:pdf',                                     "PDF"),
            ('"{name}" filetype:doc OR filetype:docx',                    "Word Document"),
            ('"{name}" filetype:xls OR filetype:xlsx',                    "Spreadsheet"),
            ('"{name}" filetype:ppt OR filetype:pptx',                    "Presentation"),
            ('"{name}" filetype:txt',                                     "Text File"),
            ('"{name}" filetype:csv',                                     "CSV Data"),
            ('"{name}" filetype:xml',                                     "XML File"),
            ('"{name}" filetype:json',                                    "JSON Data"),
            ('"{name}" filetype:sql',                                     "SQL Dump"),
            ('"{name}" filetype:log',                                     "Log File"),
            ('"{name}" filetype:bak OR filetype:backup',                  "Backup File"),
            ('"{name}" filetype:cfg OR filetype:conf OR filetype:config', "Config File"),
            ('"{name}" filetype:env',                                     ".env File"),
            ('"{name}" filetype:key OR filetype:pem',                     "Key/Cert File"),
            ('"{name}" filetype:zip OR filetype:tar OR filetype:gz',      "Archive"),
            ('"{name}" "confidential" OR "restricted" filetype:pdf',      "Confidential PDF"),
            ('"{name}" "internal use only" filetype:pdf',                 "Internal Doc"),
            ('"{name}" "not for distribution" filetype:pdf',              "NFD Document"),
        ],
    },

    # ── Images & media ────────────────────────────────────────
    "images_media": {
        "label": "Images & Media",
        "icon": "🖼️",
        "risk": "low",
        "description": "Photos, videos, and media associated with target",
        "templates": [
            ('"{name}" filetype:jpg OR filetype:jpeg',                    "JPEG Image"),
            ('"{name}" filetype:png',                                     "PNG Image"),
            ('"{name}" filetype:gif',                                     "GIF"),
            ('"{name}" filetype:mp4 OR filetype:mov',                     "Video"),
            ('"{name}" site:imgur.com',                                   "Imgur"),
            ('"{name}" site:flickr.com',                                  "Flickr"),
            ('"{name}" site:photobucket.com',                             "Photobucket"),
            ('"{name}" site:500px.com',                                   "500px"),
            ('"{name}" site:unsplash.com',                                "Unsplash"),
            ('"{name}" "photo" OR "picture" OR "headshot"',               "Photo Mention"),
            ('"{name}" "profile picture" OR "profile photo"',             "Profile Photo"),
        ],
    },

    # ── Email & phone ─────────────────────────────────────────
    "email_phone": {
        "label": "Email & Phone",
        "icon": "📧",
        "risk": "medium",
        "description": "Contact information enumeration",
        "templates": [
            ('"{name}" "@gmail.com" OR "@yahoo.com" OR "@hotmail.com" OR "@outlook.com"', "Common Email Providers"),
            ('"{name}" "@protonmail.com" OR "@pm.me" OR "@tutanota.com',  "Privacy Email"),
            ('"{name}" "contact" OR "email me" OR "reach me at"',         "Contact Info"),
            ('"{name}" "@" filetype:pdf',                                 "Email in PDF"),
            ('"{name}" intext:"phone" OR intext:"tel:" OR intext:"mobile:"', "Phone Number"),
            ('"{name}" intext:"+1-" OR intext:"+44" OR intext:"+61"',     "Intl Phone"),
            ('"{name}" "mailto:"',                                        "Mailto Link"),
            ('"{email}" site:hunter.io OR site:snov.io',                  "Email Finder"),
            ('"{name}" "whatsapp" OR "signal" OR "telegram"',             "Messaging"),
            ('"@" "{name}" site:keybase.io',                              "Keybase"),
            ('"{name}" site:gravatar.com',                                "Gravatar"),
        ],
    },

    # ── Location ──────────────────────────────────────────────
    "location": {
        "label": "Location",
        "icon": "📍",
        "risk": "medium",
        "description": "Physical location and address information",
        "templates": [
            ('"{name}" "address" OR "location" OR "located at"',          "Address"),
            ('"{name}" site:whitepages.com',                              "WhitePages"),
            ('"{name}" site:spokeo.com',                                  "Spokeo"),
            ('"{name}" site:192.com',                                     "192.com (UK)"),
            ('"{name}" site:yellowpages.com',                             "YellowPages"),
            ('"{name}" "lives in" OR "based in" OR "from" OR "residing"', "Location Mention"),
            ('"{name}" "zip code" OR "postal code" OR "postcode"',        "Postal Code"),
            ('"{name}" "street" OR "avenue" OR "road" OR "lane" OR "drive"', "Street Address"),
            ('"{name}" site:truepeoplesearch.com',                        "TruePeopleSearch"),
            ('"{name}" site:fastpeoplesearch.com',                        "FastPeopleSearch"),
            ('"{name}" site:radaris.com',                                 "Radaris"),
            ('"{name}" site:intelius.com',                                "Intelius"),
            ('"{name}" "geolocation" OR "GPS" OR "coordinates"',         "Geo Data"),
        ],
    },

    # ── Data breaches & leaks ─────────────────────────────────
    "data_breaches": {
        "label": "Breach & Leaks",
        "icon": "🔓",
        "risk": "high",
        "description": "Data breach exposure and credential leaks",
        "templates": [
            ('"{name}" site:haveibeenpwned.com',                          "HaveIBeenPwned"),
            ('"{name}" site:dehashed.com',                                "DeHashed"),
            ('"{name}" "leaked" OR "breach" OR "data dump"',              "Breach Mention"),
            ('"{name}" site:pastebin.com',                                "Pastebin"),
            ('"{name}" site:paste.ee',                                    "Paste.ee"),
            ('"{name}" site:ghostbin.co',                                 "Ghostbin"),
            ('"{name}" site:dpaste.org OR site:hastebin.com',             "Other Pastes"),
            ('"{name}" "password" OR "passwd" site:pastebin.com',         "Credentials Paste"),
            ('"{name}" "hash" site:pastebin.com',                         "Hash Paste"),
            ('"{name}" "dump" filetype:txt',                              "Text Dump"),
            ('"{name}" "combo list" OR "combolist"',                      "Combo List"),
        ],
    },

    # ── Public records ────────────────────────────────────────
    "public_records": {
        "label": "Public Records",
        "icon": "🏛️",
        "risk": "low",
        "description": "Government and legal public records",
        "templates": [
            ('"{name}" site:gov',                                         "Government Site"),
            ('"{name}" site:pacer.gov OR site:courtlistener.com',         "Court Records"),
            ('"{name}" "case number" OR "docket number"',                 "Court Case"),
            ('"{name}" site:sec.gov',                                     "SEC Filing"),
            ('"{name}" filetype:pdf site:gov',                            "Gov PDF"),
            ('"{name}" "public record" OR "FOIA" OR "freedom of information"', "FOIA Record"),
            ('"{name}" site:opencorporates.com',                          "Corporate Record"),
            ('"{name}" site:bizapedia.com OR site:corporationwiki.com',   "Business Record"),
            ('"{name}" site:votesmart.org',                               "VoteSmart"),
            ('"{name}" site:efts.sec.gov',                                "SEC EDGAR"),
            ('"{name}" "registered agent" OR "registered address"',       "Agent Info"),
            ('"{name}" site:companycheck.co.uk',                          "UK Company"),
            ('"{name}" site:companieshouse.gov.uk',                       "Companies House"),
        ],
    },

    # ── News & media coverage ─────────────────────────────────
    "news_media": {
        "label": "News & Media",
        "icon": "📰",
        "risk": "info",
        "description": "Press mentions and media coverage",
        "templates": [
            ('"{name}" site:news.google.com',                             "Google News"),
            ('"{name}" site:bbc.com OR site:bbc.co.uk',                   "BBC"),
            ('"{name}" site:reuters.com OR site:apnews.com',              "Wire Services"),
            ('"{name}" site:techcrunch.com OR site:wired.com',            "Tech Press"),
            ('"{name}" site:theguardian.com OR site:nytimes.com',         "Major Press"),
            ('"{name}" "press release"',                                  "Press Release"),
            ('"{name}" site:businesswire.com OR site:prnewswire.com',     "PR Newswire"),
            ('"{name}" inurl:article OR inurl:/news/',                    "News Article"),
            ('"{name}" "interview" OR "exclusive"',                       "Interview"),
            ('"{name}" "investigation" OR "expose" OR "scandal"',         "Investigation"),
        ],
    },

    # ── Forums & communities ──────────────────────────────────
    "forums_communities": {
        "label": "Forums & Communities",
        "icon": "💬",
        "risk": "low",
        "description": "Online community participation and forum posts",
        "templates": [
            ('"{name}" OR "{username}" site:reddit.com',                  "Reddit"),
            ('"{name}" site:quora.com',                                   "Quora"),
            ('"{name}" site:stackoverflow.com',                           "Stack Overflow"),
            ('"{username}" site:news.ycombinator.com',                    "Hacker News"),
            ('"{name}" inurl:forum OR inurl:thread OR inurl:board',       "Generic Forum"),
            ('"{username}" site:disqus.com',                              "Disqus"),
            ('"{name}" site:voat.co OR site:lemmy.world',                 "Alt Communities"),
            ('"{name}" site:boards.ie OR site:mumsnet.com',               "Regional Forums"),
            ('"{username}" "posts" OR "replies" inurl:forum',             "Forum Posts"),
            ('"{name}" site:physicsforums.com OR site:mathoverflow.net',  "Academic Forums"),
        ],
    },

    # ── Technical & developer ─────────────────────────────────
    "technical_footprint": {
        "label": "Technical Footprint",
        "icon": "💻",
        "risk": "medium",
        "description": "Developer activity, code, and technical exposure",
        "templates": [
            ('"{name}" OR "{username}" site:github.com',                  "GitHub"),
            ('"{name}" OR "{username}" site:gitlab.com',                  "GitLab"),
            ('"{name}" OR "{username}" site:bitbucket.org',               "Bitbucket"),
            ('"{username}" site:npmjs.com',                               "NPM"),
            ('"{username}" site:pypi.org',                                "PyPI"),
            ('"{name}" site:stackoverflow.com',                           "Stack Overflow"),
            ('"{name}" "ssh-rsa" OR "ssh-ed25519"',                       "SSH Key Leak"),
            ('"{name}" "api_key" OR "api key" OR "access_token"',         "API Key Leak"),
            ('"{email}" "commit" OR "author" site:github.com',            "Git Commit"),
            ('"{name}" site:hub.docker.com',                              "Docker Hub"),
            ('"{username}" site:codepen.io OR site:jsfiddle.net',         "Code Playground"),
            ('"{name}" site:hackerone.com OR site:bugcrowd.com',          "Bug Bounty"),
            ('"{name}" filetype:pem OR filetype:key OR filetype:p12',     "Private Keys"),
        ],
    },

    # ── Organisation intelligence ─────────────────────────────
    "organization_intel": {
        "label": "Organisation Intel",
        "icon": "🏢",
        "risk": "medium",
        "description": "Organisation-specific deep intelligence",
        "templates": [
            ('site:{domain} filetype:pdf',                                "Org PDFs"),
            ('site:{domain} inurl:admin OR inurl:login OR inurl:portal',  "Admin/Login"),
            ('site:{domain} inurl:wp-admin OR inurl:wp-login',            "WordPress Admin"),
            ('site:{domain} intitle:"index of"',                          "Directory Listing"),
            ('site:{domain} "confidential" OR "internal use only"',       "Confidential Doc"),
            ('site:{domain} filetype:sql OR filetype:bak OR filetype:env',"Sensitive Files"),
            ('"{org}" employees site:linkedin.com',                       "LinkedIn Employees"),
            ('"{org}" "org chart" OR "organizational chart"',             "Org Chart"),
            ('"{org}" "annual report" filetype:pdf',                      "Annual Report"),
            ('"{org}" "board of directors" OR "management team"',         "Leadership"),
            ('"{org}" site:opencorporates.com',                           "Corp Filings"),
            ('"{org}" "acquisition" OR "merger" OR "partnership"',        "M&A"),
            ('"{org}" "data breach" OR "security incident"',              "Incidents"),
            ('"{org}" "layoffs" OR "restructuring"',                      "Org Changes"),
            ('"{org}" "salary" OR "compensation" site:glassdoor.com',     "Salary Data"),
            ('"{org}" "invoice" OR "purchase order" filetype:pdf',        "Financial Docs"),
        ],
    },

    # ── Cached & archived content ─────────────────────────────
    "cached_archived": {
        "label": "Cached & Archived",
        "icon": "🗄️",
        "risk": "low",
        "description": "Deleted/cached content still accessible online",
        "templates": [
            ('"{name}" site:web.archive.org',                             "Wayback Machine"),
            ('"{name}" site:archive.ph OR site:archive.today',            "Archive.ph"),
            ('"{name}" site:cachedview.nl',                               "CachedView"),
            ('"{name}" site:timetravel.mementoweb.org',                   "Memento Web"),
            ('"cached" "{name}" site:google.com',                         "Google Cache"),
            ('"{name}" site:archive.org',                                 "Internet Archive"),
        ],
    },

    # ── Dating & personal ─────────────────────────────────────
    "dating_personal": {
        "label": "Dating & Personal",
        "icon": "❤️",
        "risk": "medium",
        "description": "Dating profiles and personal lifestyle exposure",
        "templates": [
            ('"{username}" site:tinder.com',                              "Tinder"),
            ('"{username}" site:match.com',                               "Match.com"),
            ('"{username}" site:okcupid.com',                             "OKCupid"),
            ('"{username}" site:pof.com',                                 "POF"),
            ('"{username}" site:bumble.com',                              "Bumble"),
            ('"{name}" "looking for" OR "dating" OR "single"',            "Dating Mention"),
            ('"{name}" site:meetup.com',                                  "Meetup"),
        ],
    },

    # ── Shopping & financial ──────────────────────────────────
    "shopping_financial": {
        "label": "Shopping & Financial",
        "icon": "💳",
        "risk": "medium",
        "description": "E-commerce profiles and payment information",
        "templates": [
            ('"{name}" site:ebay.com OR site:ebay.co.uk',                 "eBay"),
            ('"{name}" site:amazon.com seller',                           "Amazon Seller"),
            ('"{name}" site:etsy.com',                                    "Etsy"),
            ('"{name}" "paypal.me/{username}"',                           "PayPal.me"),
            ('"{name}" "cash.app" OR "cashapp"',                          "Cash App"),
            ('"{name}" "venmo.com"',                                      "Venmo"),
            ('"{name}" site:kickstarter.com OR site:indiegogo.com',       "Crowdfunding"),
            ('"{name}" site:patreon.com',                                 "Patreon"),
            ('"{name}" "bitcoin address" OR "eth address" OR "wallet"',   "Crypto Wallet"),
        ],
    },

    # ── Username enumeration ──────────────────────────────────
    "username_enum": {
        "label": "Username Enumeration",
        "icon": "🔍",
        "risk": "low",
        "description": "Cross-platform username footprint mapping",
        "templates": [
            ('inurl:"{username}"',                                        "Username in URL"),
            ('intitle:"{username}"',                                      "Username in Title"),
            ('"@{username}" email OR contact OR reach',                   "Email Format"),
            ('"{username}" "joined" OR "member since" OR "registered"',   "Account Age"),
            ('"{username}" -site:twitter.com -site:facebook.com',         "Elsewhere"),
            ('"{username}" site:namechk.com OR site:knowem.com',          "Name Check Sites"),
            ('"{username}" "about me" OR "bio"',                          "Profile Bio"),
        ],
    },

    # ── Geospatial / physical ─────────────────────────────────
    "geospatial": {
        "label": "Geospatial",
        "icon": "🗺️",
        "risk": "medium",
        "description": "Location check-ins, maps, and physical presence",
        "templates": [
            ('"{name}" site:foursquare.com OR site:swarm.app',            "Foursquare/Swarm"),
            ('"{name}" "check-in" OR "checked in"',                       "Check-in"),
            ('"{name}" "coordinates" OR "lat" "long"',                    "Coordinates"),
            ('"{name}" site:tripadvisor.com',                             "TripAdvisor"),
            ('"{name}" site:airbnb.com',                                  "Airbnb Host"),
            ('"{name}" "traveled to" OR "visited" OR "trip to"',          "Travel"),
            ('"{name}" "hometown" OR "from" OR "grew up in"',             "Hometown"),
        ],
    },

    # ── OPSEC & privacy leaks ─────────────────────────────────
    "opsec_leaks": {
        "label": "OPSEC / Privacy Leaks",
        "icon": "🚨",
        "risk": "high",
        "description": "Potential operational security failures and privacy leaks",
        "templates": [
            ('"{name}" "do not share" OR "off the record"',               "OTR Mention"),
            ('"{name}" "ip address" OR "my ip"',                          "IP Exposure"),
            ('"{name}" "vpn" OR "tor" OR "anonymity"',                    "Anonymity Tools"),
            ('"{name}" "phone number" "please call" OR "call me"',        "Phone Leak"),
            ('"{name}" "home address" OR "shipping address"',             "Home Address"),
            ('"{name}" "date of birth" OR "born on" OR "DOB"',            "DOB Exposure"),
            ('"{name}" "SSN" OR "social security"',                       "SSN Mention"),
            ('"{name}" "passport" OR "ID number" OR "driver license"',    "ID Document"),
            ('"{name}" "bank account" OR "routing number" OR "IBAN"',     "Banking Info"),
        ],
    },

}

# ─────────────────────────────────────────────────────────────
# RISK METADATA
# ─────────────────────────────────────────────────────────────

RISK_META = {
    "info":     {"color": "#6c757d", "badge": "#6c757d", "label": "INFO",     "emoji": "ℹ️"},
    "low":      {"color": "#0d6efd", "badge": "#0d6efd", "label": "LOW",      "emoji": "🔵"},
    "medium":   {"color": "#fd7e14", "badge": "#fd7e14", "label": "MEDIUM",   "emoji": "🟠"},
    "high":     {"color": "#dc3545", "badge": "#dc3545", "label": "HIGH",     "emoji": "🔴"},
    "critical": {"color": "#9b0000", "badge": "#ff0000", "label": "CRITICAL", "emoji": "🚨"},
}


# ─────────────────────────────────────────────────────────────
# QUERY BUILDER
# ─────────────────────────────────────────────────────────────

def build_queries(target: SearchTarget, selected_categories: Optional[List[str]] = None) -> List[Tuple[str, str, str]]:
    """
    Expand the dork database into concrete queries for this specific target.
    Returns a deduplicated list of (query_string, category_key, subcategory_label).
    """
    queries: List[Tuple[str, str, str]] = []
    seen: set = set()

    # Collect all name variants to try
    name_variants = [target.full_name] + target.aliases[:4]   # cap aliases at 4
    username_variants = target.usernames[:4] or [
        target.full_name.lower().replace(" ", ""),             # fallback synthetic username
        target.full_name.lower().replace(" ", "."),
    ]

    # Derive likely email prefix
    parts = target.full_name.lower().split()
    email_prefix = f"{parts[0]}.{parts[-1]}" if len(parts) > 1 else parts[0]

    # Derive likely domain for org
    org_domain = (target.organization.lower()
                  .replace(" ", "")
                  .replace(",", "")
                  .replace(".", "") + ".com") if target.organization else ""

    def expand(template: str, name: str, username: str) -> str:
        """Fill placeholders in a template string."""
        return (template
                .replace("{name}",     name)
                .replace("{username}", username)
                .replace("{org}",      target.organization or name)
                .replace("{domain}",   org_domain or f"{name.lower().replace(' ','')}.com")
                .replace("{email}",    f"{email_prefix}@gmail.com"))

    for cat_key, cat_data in DORK_DATABASE.items():
        # Honour --categories filter
        if selected_categories and cat_key not in selected_categories:
            continue

        # Skip org-specific intel if no org and target is a person
        if cat_key == "organization_intel" and not target.organization and target.target_type == "person":
            continue

        for template, subcategory in cat_data["templates"]:
            # Try every name × username combination (deduplicated)
            for name in name_variants:
                for uname in username_variants:
                    q = expand(template, name, uname)
                    if q not in seen:
                        seen.add(q)
                        queries.append((q, cat_key, subcategory))

    return queries


# ─────────────────────────────────────────────────────────────
# RESULT ANALYSER
# ─────────────────────────────────────────────────────────────

def analyse_result(url: str, title: str, snippet: str, category: str) -> Tuple[str, str]:
    """
    Generate a human-readable analysis note and assign/override risk level
    for a single result based on signals in URL, title, and snippet.
    Returns (analysis_text, risk_level).
    """
    u = url.lower()
    s = snippet.lower()
    base_risk = DORK_DATABASE.get(category, {}).get("risk", "info")
    notes: List[str] = []
    risk = base_risk

    # Risk levels in ascending severity order — used to ensure we never downgrade
    RISK_ORDER = ["info", "low", "medium", "high", "critical"]

    def escalate(new_risk: str):
        """Upgrade risk only — never downgrade."""
        nonlocal risk
        if RISK_ORDER.index(new_risk) > RISK_ORDER.index(risk):
            risk = new_risk

    # ── Universal high-value signals ──────────────────────────
    pii_signals = {
        ("ssn", "social security number"): ("critical", "🚨 PII: SSN/Social Security number detected."),
        ("date of birth", "dob"):          ("critical", "🚨 PII: Date of birth exposed."),
        ("passport", "passport number"):   ("critical", "🚨 PII: Passport number mentioned."),
        ("bank account", "routing number", "iban"): ("critical", "🚨 Financial: Banking details detected."),
        ("home address", "residential address"): ("high",     "🏠 Address: Residential address present."),
        ("password", "passwd", "credential"): ("critical", "🔑 Credential: Password/credential data present."),
        ("api_key", "api key", "access_token", "secret_key"): ("critical", "🔑 Token: API key or secret exposed."),
        ("ssh-rsa", "ssh-ed25519", "private key", "-----begin"): ("critical", "🔑 Key: Cryptographic key possibly exposed."),
        ("leaked", "breach", "dump", "combo"):     ("high", "💣 This content may originate from a data breach."),
    }
    for signals, (sig_risk, msg) in pii_signals.items():
        if any(sig in s for sig in signals):
            escalate(sig_risk)
            notes.append(msg)

    # ── Category-specific commentary ──────────────────────────
    if category == "social_media":
        notes.append("Social media profile confirmed; check follower count, bio, and linked accounts.")
        if "private" in s:
            notes.append("Profile may be set to private.")

    elif category == "professional":
        notes.append("Professional record found. Cross-reference employment history.")

    elif category == "documents":
        notes.append("Publicly indexed document associated with target.")
        if "confidential" in s or "restricted" in s or "internal" in s:
            escalate("high")
            notes.append("⚠️ Document appears marked Confidential/Restricted.")

    elif category == "email_phone":
        notes.append("Contact data potentially exposed. Useful for phishing risk assessment.")

    elif category == "location":
        notes.append("Location data found. May reveal home, workplace, or frequent locations.")

    elif category == "data_breaches":
        escalate("high")
        notes.append("⚠️ Target appears in a breach database or paste site.")

    elif category == "technical_footprint":
        notes.append("Developer activity linked to target. Review repo contents for secrets.")
        if "admin" in u or "login" in u:
            escalate("high")
            notes.append("🚨 Administrative access point discovered.")

    elif category == "organization_intel":
        if "admin" in u or "login" in u or "portal" in u:
            escalate("high")
            notes.append("🚨 Admin/login portal exposed on org domain.")
        elif "index of" in (title.lower() if title else ""):
            escalate("high")
            notes.append("🚨 Open directory listing on org domain.")
        elif ".sql" in u or ".bak" in u or ".env" in u:
            escalate("critical")
            notes.append("🚨 Database/backup/env file accessible on org domain!")
        else:
            notes.append("Organisation document or resource found.")

    elif category == "opsec_leaks":
        escalate("high")
        notes.append("⚠️ Potential OPSEC failure — private information inadvertently exposed.")

    elif category == "cached_archived":
        notes.append("Content may have been deleted but remains in archive. Verify current accessibility.")

    elif category == "dating_personal":
        notes.append("Personal/dating profile found. Contains lifestyle and personal preference data.")

    elif category == "geospatial":
        notes.append("Geographic data found. May help triangulate home/work locations.")

    elif category == "forums_communities":
        notes.append("Community post found. Review content for personal disclosures.")

    elif category == "username_enum":
        notes.append("Username present on this platform. Add to cross-platform correlation.")

    else:
        notes.append("Result associated with target via dork query.")

    return " ".join(notes) if notes else "Relevant result found.", risk


# ─────────────────────────────────────────────────────────────
# SEARCH EXECUTOR
# ─────────────────────────────────────────────────────────────

def execute_dork(query: str, max_results: int = 5, delay: float = 2.0) -> List[Dict]:
    """
    Run one dork query via DuckDuckGo and return raw result dicts.
    Includes retry logic with exponential backoff.
    """
    for attempt in range(3):
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
            time.sleep(delay + attempt * 0.5)   # slight increase per attempt
            return results
        except Exception as exc:
            wait = delay * (2 ** attempt)
            print(f"  [!] Query error (attempt {attempt+1}/3): {exc} — waiting {wait:.1f}s")
            time.sleep(wait)
    return []


def run_all_dorks(
    target: SearchTarget,
    queries: List[Tuple[str, str, str]],
    max_per_query: int = 5,
    delay: float = 2.0,
    max_total_queries: Optional[int] = None,
) -> List[DorkResult]:
    """
    Execute all generated dork queries and return deduplicated results.
    """
    results: List[DorkResult] = []
    seen_urls: set = set()
    total = min(len(queries), max_total_queries) if max_total_queries else len(queries)

    print(f"\n[*] Executing {total} dork queries (delay={delay}s, max_results={max_per_query} each)")
    print(f"[*] Estimated time: {total * (delay + 1):.0f}–{total * (delay + 3):.0f} seconds\n")

    for idx, (query, cat_key, subcat) in enumerate(queries[:total], 1):
        cat_label = DORK_DATABASE.get(cat_key, {}).get("label", cat_key)
        print(f"  [{idx:>4}/{total}] [{cat_label}] {query[:80]}")

        raw = execute_dork(query, max_results=max_per_query, delay=delay)

        for r in raw:
            url   = r.get("href", r.get("url", ""))
            title = r.get("title", "")
            snip  = r.get("body", r.get("snippet", ""))

            if not url or url in seen_urls:
                continue                           # skip duplicates
            seen_urls.add(url)

            analysis, risk = analyse_result(url, title, snip, cat_key)

            results.append(DorkResult(
                query=query,
                category=cat_key,
                subcategory=subcat,
                title=title,
                url=url,
                snippet=snip,
                analysis=analysis,
                risk_level=risk,
            ))

    print(f"\n[+] Collection complete: {len(results)} unique results from {total} queries.")
    return results


# ─────────────────────────────────────────────────────────────
# HTML REPORT GENERATOR
# ─────────────────────────────────────────────────────────────

def _risk_badge(risk: str) -> str:
    """Return an HTML badge span for a risk level."""
    m = RISK_META.get(risk, RISK_META["info"])
    return (f'<span class="badge risk-{risk}">'
            f'{m["emoji"]} {m["label"]}'
            f'</span>')


def generate_html_report(
    target: SearchTarget,
    results: List[DorkResult],
    output_path: str,
    queries_run: int,
    duration_seconds: float,
) -> str:
    """
    Build and write a self-contained HTML report.
    Returns the path written.
    """

    now_str   = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    date_slug = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Aggregate statistics ───────────────────────────────────
    by_category: Dict[str, List[DorkResult]] = defaultdict(list)
    by_risk:     Dict[str, int]               = defaultdict(int)
    for r in results:
        by_category[r.category].append(r)
        by_risk[r.risk_level] += 1

    total = len(results)
    cats_found = [k for k in DORK_DATABASE if k in by_category]

    # ── Sidebar category nav ───────────────────────────────────
    sidebar_html = ""
    for cat_key in DORK_DATABASE:
        if cat_key not in by_category:
            continue
        cat   = DORK_DATABASE[cat_key]
        count = len(by_category[cat_key])
        sidebar_html += (
            f'<a href="#cat-{cat_key}" class="sidebar-link">'
            f'{cat["icon"]} {cat["label"]}'
            f'<span class="count-badge">{count}</span>'
            f'</a>\n'
        )

    # ── Result cards per category ──────────────────────────────
    results_html = ""
    for cat_key in DORK_DATABASE:
        if cat_key not in by_category:
            continue
        cat    = DORK_DATABASE[cat_key]
        rlist  = by_category[cat_key]

        results_html += f'''
        <section class="cat-section" id="cat-{cat_key}" data-cat="{cat_key}">
          <div class="cat-header">
            <span class="cat-icon">{cat["icon"]}</span>
            <div>
              <h2 class="cat-title">{cat["label"]}</h2>
              <p class="cat-desc">{html_lib.escape(cat["description"])}</p>
            </div>
            <span class="cat-count">{len(rlist)} result{"s" if len(rlist)!=1 else ""}</span>
          </div>
        '''

        for res in sorted(rlist, key=lambda x: list(RISK_META).index(x.risk_level), reverse=True):
            safe_title   = html_lib.escape(res.title or "(no title)")
            safe_url     = html_lib.escape(res.url)
            safe_snip    = html_lib.escape(res.snippet or "")
            safe_query   = html_lib.escape(res.query)
            safe_analysis= html_lib.escape(res.analysis)
            safe_subcat  = html_lib.escape(res.subcategory)

            results_html += f'''
          <div class="result-card risk-border-{res.risk_level}" data-risk="{res.risk_level}">
            <div class="result-header">
              <div class="result-meta">
                {_risk_badge(res.risk_level)}
                <span class="subcat-tag">{safe_subcat}</span>
              </div>
              <h3 class="result-title">
                <a href="{safe_url}" target="_blank" rel="noopener noreferrer">{safe_title}</a>
              </h3>
              <p class="result-url">{safe_url}</p>
            </div>
            <div class="result-body">
              <p class="result-snippet">{safe_snip}</p>
              <div class="analysis-box">
                <strong>🔎 Analysis:</strong> {safe_analysis}
              </div>
              <details class="query-detail">
                <summary>Dork Query Used</summary>
                <code>{safe_query}</code>
              </details>
            </div>
          </div>'''

        results_html += "\n        </section>\n"

    # ── Risk summary bar data ──────────────────────────────────
    risk_bars = ""
    for rl in ["critical","high","medium","low","info"]:
        cnt = by_risk.get(rl, 0)
        pct = (cnt / total * 100) if total else 0
        m   = RISK_META[rl]
        risk_bars += f'''
        <div class="risk-bar-row">
          <span class="risk-label" style="color:{m["color"]}">{m["emoji"]} {m["label"]}</span>
          <div class="risk-bar-bg">
            <div class="risk-bar-fill" style="width:{pct:.1f}%;background:{m["badge"]}"></div>
          </div>
          <span class="risk-count">{cnt}</span>
        </div>'''

    # ── Category summary cards ────────────────────────────────
    summary_cards = ""
    for cat_key in cats_found:
        cat   = DORK_DATABASE[cat_key]
        count = len(by_category[cat_key])
        # highest risk in this category
        hr    = sorted(
            [r.risk_level for r in by_category[cat_key]],
            key=lambda x: list(RISK_META).index(x),
            reverse=True
        )[0]
        summary_cards += f'''
        <a href="#cat-{cat_key}" class="summary-card risk-border-{hr}">
          <span class="s-icon">{cat["icon"]}</span>
          <span class="s-label">{cat["label"]}</span>
          <span class="s-count">{count}</span>
        </a>'''

    # ── Socials table ─────────────────────────────────────────
    socials_rows = ""
    if target.socials:
        for platform, handle in target.socials.items():
            socials_rows += f"<tr><td>{html_lib.escape(platform)}</td><td>{html_lib.escape(handle)}</td></tr>"

    # ── Full HTML ─────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OSINT Report — {html_lib.escape(target.full_name)}</title>
  <style>
    /* ── Reset & base ─────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg:       #0d1117;
      --surface:  #161b22;
      --surface2: #21262d;
      --border:   #30363d;
      --text:     #c9d1d9;
      --text-dim: #8b949e;
      --accent:   #58a6ff;
      --green:    #3fb950;
      --red:      #f85149;
      --orange:   #d29922;
      --purple:   #bc8cff;
      --font:     'Segoe UI', system-ui, -apple-system, sans-serif;
      --mono:     'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    }}
    html {{ scroll-behavior: smooth; }}
    body {{
      font-family: var(--font);
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      display: flex;
      min-height: 100vh;
    }}

    /* ── Scrollbar ────────────────────────────────────────── */
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}

    /* ── Sidebar ──────────────────────────────────────────── */
    #sidebar {{
      width: 220px;
      min-width: 220px;
      background: var(--surface);
      border-right: 1px solid var(--border);
      padding: 1rem 0;
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
      flex-shrink: 0;
    }}
    .sidebar-brand {{
      padding: 0.75rem 1rem 1rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 0.5rem;
    }}
    .sidebar-brand h1 {{ font-size: 0.85rem; color: var(--accent); letter-spacing: 1px; text-transform: uppercase; }}
    .sidebar-brand p  {{ font-size: 0.75rem; color: var(--text-dim); margin-top: 0.2rem; }}
    .sidebar-link {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.45rem 1rem;
      color: var(--text-dim);
      text-decoration: none;
      font-size: 0.82rem;
      transition: background 0.15s, color 0.15s;
    }}
    .sidebar-link:hover {{ background: var(--surface2); color: var(--text); }}
    .count-badge {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1px 6px;
      font-size: 0.72rem;
      color: var(--text-dim);
    }}
    .sidebar-section {{ padding: 0.4rem 1rem 0.1rem; font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }}

    /* ── Main content ─────────────────────────────────────── */
    #main {{ flex: 1; overflow-x: hidden; padding: 2rem; max-width: calc(100vw - 220px); }}

    /* ── Top banner ───────────────────────────────────────── */
    .report-header {{
      background: linear-gradient(135deg, var(--surface) 0%, #1a2233 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem 2rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: flex-start;
      gap: 1.5rem;
    }}
    .report-header .header-icon {{ font-size: 3rem; flex-shrink: 0; }}
    .report-title {{ font-size: 1.7rem; font-weight: 700; color: var(--text); margin-bottom: 0.2rem; }}
    .report-meta  {{ font-size: 0.82rem; color: var(--text-dim); }}
    .report-meta span {{ margin-right: 1.5rem; }}

    /* ── Warning banner ──────────────────────────────────── */
    .legal-banner {{
      background: #1a1200;
      border: 1px solid #6d4c00;
      border-radius: 8px;
      padding: 0.75rem 1.2rem;
      font-size: 0.8rem;
      color: #d29922;
      margin-bottom: 1.5rem;
    }}

    /* ── Stats row ────────────────────────────────────────── */
    .stats-row {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
    .stat-card {{
      flex: 1; min-width: 130px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem 1.2rem;
      text-align: center;
    }}
    .stat-num  {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
    .stat-label{{ font-size: 0.78rem; color: var(--text-dim); margin-top: 0.2rem; }}

    /* ── Two-col layout ──────────────────────────────────── */
    .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.2rem; margin-bottom: 1.5rem; }}
    @media (max-width: 900px) {{ .two-col {{ grid-template-columns: 1fr; }} }}

    /* ── Info panel ──────────────────────────────────────── */
    .info-panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.2rem 1.5rem;
    }}
    .info-panel h3 {{ font-size: 0.9rem; color: var(--accent); margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }}
    .info-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    .info-table td {{ padding: 0.35rem 0; }}
    .info-table td:first-child {{ color: var(--text-dim); width: 40%; }}
    .info-table td:last-child  {{ color: var(--text); font-weight: 500; }}

    /* ── Risk distribution ────────────────────────────────── */
    .risk-bar-row {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.6rem; font-size: 0.82rem; }}
    .risk-label  {{ width: 90px; font-weight: 600; white-space: nowrap; }}
    .risk-bar-bg {{ flex: 1; background: var(--surface2); border-radius: 4px; height: 10px; overflow: hidden; }}
    .risk-bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
    .risk-count  {{ width: 30px; text-align: right; color: var(--text-dim); }}

    /* ── Summary cards grid ──────────────────────────────── */
    .summary-grid {{ display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 1.5rem; }}
    .summary-card {{
      display: flex; align-items: center; gap: 0.5rem;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 0.5rem 0.9rem;
      text-decoration: none; color: var(--text); font-size: 0.82rem;
      transition: border-color 0.2s, background 0.2s;
    }}
    .summary-card:hover {{ background: var(--surface2); }}
    .s-icon  {{ font-size: 1rem; }}
    .s-label {{ flex: 1; }}
    .s-count {{ background: var(--surface2); border-radius: 10px; padding: 1px 7px; font-size: 0.75rem; color: var(--text-dim); }}

    /* ── Category section ────────────────────────────────── */
    .cat-section {{ margin-bottom: 2.5rem; }}
    .cat-header {{
      display: flex; align-items: center; gap: 1rem;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px 10px 0 0; padding: 1rem 1.5rem;
      margin-bottom: 0.5rem;
    }}
    .cat-icon  {{ font-size: 1.6rem; }}
    .cat-title {{ font-size: 1.15rem; font-weight: 700; color: var(--text); }}
    .cat-desc  {{ font-size: 0.8rem; color: var(--text-dim); margin-top: 0.1rem; }}
    .cat-count {{ margin-left: auto; background: var(--surface2); border: 1px solid var(--border); border-radius: 12px; padding: 3px 10px; font-size: 0.8rem; color: var(--text-dim); }}

    /* ── Result card ─────────────────────────────────────── */
    .result-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-left-width: 4px;
      border-radius: 0 0 8px 8px;
      margin-bottom: 0.6rem;
      overflow: hidden;
    }}
    .result-header {{ padding: 0.8rem 1.2rem 0.4rem; }}
    .result-meta   {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }}
    .result-title  {{ font-size: 0.95rem; margin-bottom: 0.2rem; }}
    .result-title a {{ color: var(--accent); text-decoration: none; }}
    .result-title a:hover {{ text-decoration: underline; }}
    .result-url    {{ font-size: 0.75rem; color: var(--green); font-family: var(--mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .result-body   {{ padding: 0 1.2rem 0.8rem; }}
    .result-snippet {{ font-size: 0.82rem; color: var(--text-dim); margin-bottom: 0.6rem; }}
    .analysis-box {{
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.6rem 0.9rem;
      font-size: 0.82rem;
      color: var(--text);
      margin-bottom: 0.5rem;
    }}
    .query-detail {{ font-size: 0.78rem; color: var(--text-dim); }}
    .query-detail summary {{ cursor: pointer; padding: 0.2rem 0; }}
    .query-detail code {{ display: block; background: var(--surface2); border-radius: 4px; padding: 0.4rem 0.7rem; margin-top: 0.3rem; font-family: var(--mono); font-size: 0.75rem; color: var(--purple); white-space: pre-wrap; word-break: break-all; }}

    /* ── Badges ──────────────────────────────────────────── */
    .badge {{
      display: inline-block; border-radius: 4px; padding: 2px 8px;
      font-size: 0.72rem; font-weight: 700; letter-spacing: 0.5px;
      color: #fff;
    }}
    .badge.risk-info     {{ background: #6c757d; }}
    .badge.risk-low      {{ background: #0d6efd; }}
    .badge.risk-medium   {{ background: #fd7e14; }}
    .badge.risk-high     {{ background: #dc3545; }}
    .badge.risk-critical {{ background: #9b0000; border: 1px solid #ff0000; }}
    .subcat-tag {{
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 4px; padding: 2px 7px; font-size: 0.72rem; color: var(--text-dim);
    }}

    /* ── Risk border variants ────────────────────────────── */
    .risk-border-info     {{ border-left-color: #6c757d; }}
    .risk-border-low      {{ border-left-color: #0d6efd; }}
    .risk-border-medium   {{ border-left-color: #fd7e14; }}
    .risk-border-high     {{ border-left-color: #dc3545; }}
    .risk-border-critical {{ border-left-color: #ff0000; }}

    /* ── Filter controls ─────────────────────────────────── */
    .filter-bar {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.8rem 1.2rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 0.8rem;
      flex-wrap: wrap;
    }}
    .filter-bar label {{ font-size: 0.82rem; color: var(--text-dim); }}
    .filter-btn {{
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 6px; padding: 4px 10px; font-size: 0.78rem;
      color: var(--text); cursor: pointer; transition: all 0.15s;
    }}
    .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #0d1117; border-color: var(--accent); }}
    .search-box {{
      margin-left: auto;
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 6px; padding: 4px 10px; font-size: 0.82rem;
      color: var(--text); outline: none; width: 220px;
    }}
    .search-box::placeholder {{ color: var(--text-dim); }}

    /* ── Footer ──────────────────────────────────────────── */
    .report-footer {{
      border-top: 1px solid var(--border); padding-top: 1.5rem;
      margin-top: 2rem; font-size: 0.78rem; color: var(--text-dim); text-align: center;
    }}

    /* ── No-print sidebar on print ────────────────────────── */
    @media print {{
      #sidebar {{ display: none; }}
      #main {{ max-width: 100%; }}
    }}
  </style>
</head>
<body>

<!-- ═══════════════════════ SIDEBAR ═══════════════════════════ -->
<nav id="sidebar">
  <div class="sidebar-brand">
    <h1>🕵️ OSINT Tool</h1>
    <p>{html_lib.escape(target.full_name)}</p>
  </div>
  <div class="sidebar-section">Categories</div>
  {sidebar_html}
</nav>

<!-- ═══════════════════════ MAIN ══════════════════════════════ -->
<main id="main">

  <!-- Header -->
  <div class="report-header">
    <div class="header-icon">🕵️</div>
    <div>
      <div class="report-title">OSINT Report: {html_lib.escape(target.full_name)}</div>
      <div class="report-meta">
        <span>📅 Generated: {now_str}</span>
        <span>🔍 Queries: {queries_run}</span>
        <span>📦 Results: {total}</span>
        <span>⏱️ Duration: {duration_seconds:.1f}s</span>
        <span>🎯 Type: {target.target_type.capitalize()}</span>
      </div>
    </div>
  </div>

  <!-- Legal warning -->
  <div class="legal-banner">
    ⚠️ <strong>Legal Notice:</strong> This report was generated using publicly available information via legal OSINT techniques.
    Use only for authorised security research, due diligence, or self-investigation. Unauthorised use to stalk, harass,
    or harm individuals may violate local laws. The tool author assumes no liability for misuse.
  </div>

  <!-- Stats row -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-num">{total}</div>
      <div class="stat-label">Total Results</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#f85149">{by_risk.get('critical',0) + by_risk.get('high',0)}</div>
      <div class="stat-label">High+ Risk</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#d29922">{by_risk.get('medium',0)}</div>
      <div class="stat-label">Medium Risk</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#3fb950">{len(cats_found)}</div>
      <div class="stat-label">Categories Hit</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">{queries_run}</div>
      <div class="stat-label">Dorks Executed</div>
    </div>
  </div>

  <!-- Two-col: target info + risk distribution -->
  <div class="two-col">

    <div class="info-panel">
      <h3>🎯 Target Profile</h3>
      <table class="info-table">
        <tr><td>Full Name</td><td>{html_lib.escape(target.full_name)}</td></tr>
        <tr><td>Type</td><td>{target.target_type.capitalize()}</td></tr>
        <tr><td>Aliases</td><td>{html_lib.escape(", ".join(target.aliases) or "—")}</td></tr>
        <tr><td>Usernames</td><td>{html_lib.escape(", ".join(target.usernames) or "—")}</td></tr>
        <tr><td>Organisation</td><td>{html_lib.escape(target.organization or "—")}</td></tr>
        <tr><td>Location</td><td>{html_lib.escape(target.location or "—")}</td></tr>
        {"<tr><td>Socials</td><td>" + html_lib.escape(", ".join(f"{p}:{h}" for p,h in target.socials.items())) + "</td></tr>" if target.socials else ""}
      </table>
    </div>

    <div class="info-panel">
      <h3>⚠️ Risk Distribution</h3>
      {risk_bars}
    </div>

  </div>

  <!-- Category hit grid -->
  <div class="summary-grid">
    {summary_cards}
  </div>

  <!-- Filter bar -->
  <div class="filter-bar">
    <label>Filter by risk:</label>
    <button class="filter-btn active" onclick="filterRisk('all', this)">All</button>
    <button class="filter-btn" onclick="filterRisk('critical', this)">🚨 Critical</button>
    <button class="filter-btn" onclick="filterRisk('high', this)">🔴 High</button>
    <button class="filter-btn" onclick="filterRisk('medium', this)">🟠 Medium</button>
    <button class="filter-btn" onclick="filterRisk('low', this)">🔵 Low</button>
    <button class="filter-btn" onclick="filterRisk('info', this)">ℹ️ Info</button>
    <input class="search-box" type="text" placeholder="🔍 Search results…" oninput="liveSearch(this.value)">
  </div>

  <!-- Results by category -->
  {results_html}

  <!-- Footer -->
  <div class="report-footer">
    Generated by <strong>OSINT Dorking Tool v2.0</strong> · {now_str} ·
    Search engine: DuckDuckGo (no API key) ·
    {queries_run} queries executed · {total} unique results collected
  </div>

</main>

<script>
  // ── Risk filter ───────────────────────────────────────────
  function filterRisk(level, btn) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.result-card').forEach(card => {{
      if (level === 'all' || card.dataset.risk === level) {{
        card.style.display = '';
      }} else {{
        card.style.display = 'none';
      }}
    }});
    // Hide empty sections
    document.querySelectorAll('.cat-section').forEach(sec => {{
      const visible = [...sec.querySelectorAll('.result-card')].some(c => c.style.display !== 'none');
      sec.style.display = visible ? '' : 'none';
    }});
  }}

  // ── Live search ───────────────────────────────────────────
  function liveSearch(query) {{
    const q = query.toLowerCase();
    document.querySelectorAll('.result-card').forEach(card => {{
      const text = card.textContent.toLowerCase();
      card.style.display = (q === '' || text.includes(q)) ? '' : 'none';
    }});
    document.querySelectorAll('.cat-section').forEach(sec => {{
      const visible = [...sec.querySelectorAll('.result-card')].some(c => c.style.display !== 'none');
      sec.style.display = visible ? '' : 'none';
    }});
  }}

  // ── Sidebar active highlight on scroll ───────────────────
  const sections = document.querySelectorAll('.cat-section');
  const links    = document.querySelectorAll('.sidebar-link');
  const observer = new IntersectionObserver(entries => {{
    entries.forEach(e => {{
      if (e.isIntersecting) {{
        links.forEach(l => l.style.color = '');
        const id = e.target.id;
        const active = document.querySelector(`.sidebar-link[href="#${{id}}"]`);
        if (active) active.style.color = '#58a6ff';
      }}
    }});
  }}, {{ threshold: 0.2 }});
  sections.forEach(s => observer.observe(s));
</script>

</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


# ─────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="OSINT Dorking Tool — automated search-engine intelligence gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Person investigation
  python dork_tool.py --target "Jane Doe" --aliases "Jan Doe" --usernames "janedoe,j_doe99" \\
    --socials "twitter:janedoe,github:janedoe99" --org "Acme Corp" --location "New York"

  # Organisation investigation
  python dork_tool.py --target "Acme Corp" --type organization --org "Acme Corp"

  # Quick scan — fewer categories
  python dork_tool.py --target "Jane Doe" --categories social_media,email_phone,documents

  # Slow/safe mode (avoid rate-limiting)
  python dork_tool.py --target "Jane Doe" --delay 4.0 --max-total 60

Available categories:
  """ + ", ".join(DORK_DATABASE.keys())
    )

    parser.add_argument("--target",     required=True, help="Primary name of the target")
    parser.add_argument("--aliases",    default="",    help="Comma-separated list of aliases/nicknames")
    parser.add_argument("--usernames",  default="",    help="Comma-separated list of online usernames/handles")
    parser.add_argument("--socials",    default="",    help="Comma-separated platform:handle pairs (e.g. twitter:johndoe)")
    parser.add_argument("--org",        default="",    help="Organisation name (employer / company being investigated)")
    parser.add_argument("--location",   default="",    help="Known location (city, country)")
    parser.add_argument("--type",       default="person", choices=["person","organization"], help="Target type")
    parser.add_argument("--categories", default="",    help="Comma-separated category keys to run (default: all)")
    parser.add_argument("--delay",      type=float, default=2.0, help="Seconds between queries (default: 2.0)")
    parser.add_argument("--max-per-query", type=int, default=5,  help="Max results per dork query (default: 5)")
    parser.add_argument("--max-total",  type=int, default=None,  help="Max total queries to run (default: unlimited)")
    parser.add_argument("--output",     default="",    help="Output HTML file path (default: auto-generated)")
    parser.add_argument("--dry-run",    action="store_true",     help="Print queries without executing searches")
    parser.add_argument("--list-categories", action="store_true", help="Print all available categories and exit")

    return parser.parse_args()


def main():
    args = parse_args()

    # ── List categories ────────────────────────────────────────
    if args.list_categories:
        print("\nAvailable dork categories:\n")
        for key, data in DORK_DATABASE.items():
            print(f"  {data['icon']} {key:<25} — {data['description']} ({len(data['templates'])} templates)")
        print()
        sys.exit(0)

    # ── Build target ───────────────────────────────────────────
    target = SearchTarget(
        full_name   = args.target.strip(),
        aliases     = [a.strip() for a in args.aliases.split(",")   if a.strip()],
        usernames   = [u.strip() for u in args.usernames.split(",") if u.strip()],
        socials     = {p.split(":")[0].strip(): p.split(":")[1].strip()
                       for p in args.socials.split(",") if ":" in p},
        organization= args.org.strip(),
        location    = args.location.strip(),
        target_type = args.type,
    )

    selected_cats = [c.strip() for c in args.categories.split(",") if c.strip()] or None

    print(f"""
╔══════════════════════════════════════════════════════╗
║              OSINT DORKING TOOL v2.0                 ║
╚══════════════════════════════════════════════════════╝
  Target    : {target.full_name}
  Type      : {target.target_type}
  Aliases   : {', '.join(target.aliases) or '—'}
  Usernames : {', '.join(target.usernames) or '—'}
  Org       : {target.organization or '—'}
  Location  : {target.location or '—'}
  Socials   : {', '.join(f"{p}:{h}" for p,h in target.socials.items()) or '—'}
  Categories: {', '.join(selected_cats) if selected_cats else 'ALL'}
  Delay     : {args.delay}s
""")

    # ── Build queries ──────────────────────────────────────────
    queries = build_queries(target, selected_cats)
    print(f"[*] Generated {len(queries)} unique dork queries from database.")

    if args.dry_run:
        print("\n── DRY RUN — first 20 queries ──────────────────────────\n")
        for i, (q, cat, sub) in enumerate(queries[:20], 1):
            print(f"  {i:>3}. [{cat}] {q}")
        print(f"\n... and {max(0, len(queries)-20)} more. (remove --dry-run to execute)\n")
        sys.exit(0)

    # ── Output path ────────────────────────────────────────────
    if args.output:
        out_path = args.output
    else:
        slug = re.sub(r"[^a-z0-9]+", "_", target.full_name.lower()).strip("_")
        date = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"osint_{slug}_{date}.html"

    # ── Execute ────────────────────────────────────────────────
    t_start  = time.time()
    results  = run_all_dorks(
        target,
        queries,
        max_per_query=args.max_per_query,
        delay=args.delay,
        max_total_queries=args.max_total,
    )
    duration = time.time() - t_start

    # ── Generate report ────────────────────────────────────────
    queries_run = min(len(queries), args.max_total) if args.max_total else len(queries)
    report_path = generate_html_report(target, results, out_path, queries_run, duration)

    print(f"\n[✓] Report written → {report_path}")
    print(f"    Open with: python -m http.server 8000  (then visit http://localhost:8000/{out_path})")
    print(f"    Or simply open the file directly in your browser.\n")


if __name__ == "__main__":
    main()
