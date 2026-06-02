#!/usr/bin/env python3
"""
CyberIntel Discord Bot
======================
Your Discord channels:
  @threat-intel   → APT reports, breach news, threat intel (Krebs, Mandiant, Unit42, etc.)
  #cve-updates    → All CVEs from NVD + CISA KEV (CVSS >= 7.0)
  #bug-bounty     → HackerOne disclosures, Exploit-DB, bug bounty writeups
  #daily-news     → Daily digest: BleepingComputer, HackerNews, Dark Reading, SANS ISC
  #tools-resources→ GitHub security tools, ArXiv research, project zero writeups
 
Runs on GitHub Actions — free, no server needed.
Deduplication via sent_ids.json cached between runs.
"""
 
import os
import json
import time
import hashlib
import logging
import requests
import feedparser
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
 
# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cyberintel")
 
# ── Webhooks → YOUR exact channel names ──────────────────────────────────────
# Set each of these as a GitHub Secret (Settings → Secrets → Actions)
WEBHOOKS = {
    "threat_intel":    os.getenv("DISCORD_THREAT_INTEL"),    # @threat-intel
    "cve_updates":     os.getenv("DISCORD_CVE_UPDATES"),     # #cve-updates
    "bug_bounty":      os.getenv("DISCORD_BUG_BOUNTY"),      # #bug-bounty
    "daily_news":      os.getenv("DISCORD_DAILY_NEWS"),      # #daily-news
    "tools_resources": os.getenv("DISCORD_TOOLS_RESOURCES"), # #tools-resources
}
 
# ── Discord embed colors ──────────────────────────────────────────────────────
COLORS = {
    "critical": 0xFF0000,   # red       — CVSS >= 9.0
    "high":     0xFF6B35,   # orange    — CVSS 7.0–8.9
    "bounty":   0xF1C40F,   # gold      — bug bounty / exploit
    "tool":     0x2ECC71,   # green     — tools & research
    "news":     0x5865F2,   # blurple   — daily news
    "intel":    0xE74C3C,   # crimson   — threat intel / APT
}
 
# ── Dedup cache ───────────────────────────────────────────────────────────────
CACHE_FILE = "sent_ids.json"
MAX_CACHE  = 2000
 
def load_cache() -> set:
    try:
        with open(CACHE_FILE) as f:
            return set(json.load(f))
    except Exception:
        return set()
 
def save_cache(cache: set):
    with open(CACHE_FILE, "w") as f:
        json.dump(list(cache)[-MAX_CACHE:], f)
 
def make_id(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()
 
# ── Discord sender ────────────────────────────────────────────────────────────
def send_embed(webhook_key: str, title: str, description: str,
               url: str, color_key: str = "news", mention: str = None) -> bool:
    """Send a rich embed to Discord. Returns True on success."""
    webhook_url = WEBHOOKS.get(webhook_key)
    if not webhook_url:
        log.warning("Webhook not configured: %s — skipping", webhook_key)
        return False
 
    payload = {
        "username":   "CyberIntel Bot 🛡️",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2716/2716652.png",
        "content":    mention or "",
        "embeds": [{
            "title":       title[:256],
            "description": description[:2000],
            "url":         url,
            "color":       COLORS.get(color_key, COLORS["news"]),
            "footer":      {"text": "CyberIntel Bot • Free Intel, Zero Cost"},
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }],
    }
 
    for attempt in range(3):
        try:
            resp = requests.post(webhook_url, json=payload, timeout=10)
            if resp.status_code == 204:
                return True
            if resp.status_code == 429:
                wait = float(resp.json().get("retry_after", 5))
                log.warning("Rate limited — waiting %.1fs", wait)
                time.sleep(wait)
                continue
            log.error("Discord %s error: %s", resp.status_code, resp.text[:150])
            return False
        except requests.RequestException as e:
            log.error("Request error (attempt %d): %s", attempt + 1, e)
            time.sleep(3)
    return False
 
 
# ════════════════════════════════════════════════════════════════════════════
#  #cve-updates — NVD / NIST CVE API
#  All CVEs CVSS >= 7.0 from the last 24 hours
#
#  NVD API rate limits:
#    No API key → 5 requests per 30s, frequent empty responses
#    Free API key → 50 requests per 30s, much more reliable
#  Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
#  Add it as GitHub Secret: NVD_API_KEY
# ════════════════════════════════════════════════════════════════════════════
def fetch_nvd_cves(min_cvss: float = 7.0, hours: int = 24) -> list:
    log.info("Fetching NVD CVEs (CVSS >= %.1f)...", min_cvss)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url   = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={since}&resultsPerPage=50"
 
    # Use API key if available — much more reliable
    nvd_api_key = os.getenv("NVD_API_KEY", "")
    headers = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
        log.info("NVD: using API key (higher rate limit)")
    else:
        log.warning("NVD: no API key — get a free one at https://nvd.nist.gov/developers/request-an-api-key")
 
    # Retry up to 3 times — NVD often returns empty without a key
    for attempt in range(3):
        try:
            if attempt > 0:
                wait = 6 * attempt   # 6s then 12s
                log.info("NVD retry %d/3 — waiting %ds...", attempt + 1, wait)
                time.sleep(wait)
 
            resp = requests.get(url, headers=headers, timeout=30)
 
            if resp.status_code == 403:
                log.warning("NVD rate limited (403) — waiting 30s")
                time.sleep(30)
                continue
 
            if not resp.text or not resp.text.strip():
                log.warning("NVD empty response (attempt %d)", attempt + 1)
                continue
 
            data  = resp.json()
            items = []
            for vuln in data.get("vulnerabilities", []):
                cve    = vuln["cve"]
                cve_id = cve["id"]
                metrics = cve.get("metrics", {})
                score   = 0.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        score = entries[0].get("cvssData", {}).get("baseScore", 0.0)
                        break
                if score < min_cvss:
                    continue
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description available."
                )
                is_critical = score >= 9.0
                items.append({
                    "id":      cve_id,
                    "title":   f"{'🔴 CRITICAL' if is_critical else '🟠 HIGH'} | {cve_id} — CVSS {score}",
                    "desc":    (
                        f"{desc[:350]}{'...' if len(desc) > 350 else ''}\n\n"
                        f"**CVSS Score:** {score}/10  |  "
                        f"**Severity:** {'Critical' if is_critical else 'High'}"
                    ),
                    "url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "webhook": "cve_updates",
                    "color":   "critical" if is_critical else "high",
                    "mention": "@everyone 🚨 Critical CVE — patch immediately!" if is_critical else None,
                })
            log.info("NVD: %d CVEs found", len(items))
            return items
 
        except ValueError as e:
            log.warning("NVD bad JSON (attempt %d): %s", attempt + 1, e)
        except requests.RequestException as e:
            log.warning("NVD request error (attempt %d): %s", attempt + 1, e)
 
    log.error("NVD failed after 3 attempts — skipping this run")
    return []
 
 
# ════════════════════════════════════════════════════════════════════════════
#  #cve-updates — CVE FALLBACK SOURCES (when NVD is down)
#  These kick in automatically if NVD returns nothing
# ════════════════════════════════════════════════════════════════════════════
def fetch_cve_mitre_rss() -> list:
    """MITRE CVE RSS feed — reliable alternative to NVD API."""
    log.info("CVE Fallback: fetching MITRE CVE RSS...")
    try:
        feed  = feedparser.parse("https://cve.mitre.org/data/downloads/allitems-cvrf-year-2026.xml")
        # MITRE XML is large — use their news feed instead
        feed  = feedparser.parse("https://www.cve.org/Media/News/item-feed.rss")
        items = []
        for entry in feed.entries[:10]:
            title   = entry.get("title", "")
            link    = entry.get("link", "")
            summary = entry.get("summary", "")
            if summary:
                summary = BeautifulSoup(summary, "html.parser").get_text()[:300]
            items.append({
                "id":      make_id(link or title),
                "title":   f"🟠 [CVE.ORG] {title}",
                "desc":    summary or "New CVE published. Click for details.",
                "url":     link,
                "webhook": "cve_updates",
                "color":   "high",
                "mention": None,
            })
        log.info("MITRE CVE RSS: %d items", len(items))
        return items
    except Exception as e:
        log.error("MITRE CVE RSS failed: %s", e)
        return []
 
def fetch_vulndb_rss() -> list:
    """VulnDB / Vulnerability Lab RSS — another NVD fallback."""
    log.info("CVE Fallback: fetching Vulnerability Lab RSS...")
    sources = [
        ("https://www.vulnerability-lab.com/rss/rss.php",    "Vulnerability Lab"),
        ("https://seclists.org/rss/fulldisclosure.rss",       "Full Disclosure"),
        ("https://packetstormsecurity.com/feeds/vulnerabilities/","Packet Storm CVEs"),
    ]
    items = []
    for feed_url, label in sources:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:5]:
                title   = entry.get("title", "")
                link    = entry.get("link", "")
                summary = entry.get("summary", "")
                if summary:
                    summary = BeautifulSoup(summary, "html.parser").get_text()[:300]
                items.append({
                    "id":      make_id(link or title),
                    "title":   f"🟠 [{label}] {title}",
                    "desc":    summary or "Click to read full details.",
                    "url":     link,
                    "webhook": "cve_updates",
                    "color":   "high",
                    "mention": None,
                })
            log.info("  %s: %d items", label, len(items))
        except Exception as e:
            log.error("Fallback RSS %s failed: %s", label, e)
    return items
 
# ════════════════════════════════════════════════════════════════════════════
#  #cve-updates — CISA Known Exploited Vulnerabilities
#  These are CVEs actively being exploited RIGHT NOW
# ════════════════════════════════════════════════════════════════════════════
def fetch_cisa_kev(hours: int = 24) -> list:
    log.info("Fetching CISA KEV...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        data   = requests.get(url, timeout=20).json()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        items  = []
        for v in data.get("vulnerabilities", []):
            try:
                added_dt = datetime.strptime(v.get("dateAdded",""), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if added_dt < cutoff:
                continue
            cve_id = v.get("cveID", "UNKNOWN")
            items.append({
                "id":      f"kev-{cve_id}",
                "title":   f"🚨 ACTIVELY EXPLOITED | {cve_id} — {v.get('vendorProject','')} {v.get('product','')}",
                "desc":    (
                    f"**Vulnerability:** {v.get('vulnerabilityName','N/A')}\n"
                    f"**Required action:** {v.get('requiredAction','N/A')}\n"
                    f"**Patch deadline:** {v.get('dueDate','N/A')}\n\n"
                    f"⚠️ CISA has confirmed this is being actively exploited in the wild."
                ),
                "url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "webhook": "cve_updates",
                "color":   "critical",
                "mention": "@everyone ⚠️ Exploited in the Wild — CISA KEV",
            })
        log.info("CISA KEV: %d new entries", len(items))
        return items
    except Exception as e:
        log.error("CISA KEV failed: %s", e)
        return []
# ════════════════════════════════════════════════════════════════════════════
#  #daily-news — RSS feeds (general security news)
# ════════════════════════════════════════════════════════════════════════════
DAILY_NEWS_FEEDS = [
    ("https://www.bleepingcomputer.com/feed/",          "Bleeping Computer"),
    ("https://feeds.feedburner.com/TheHackersNews",     "The Hacker News"),
    ("https://isc.sans.edu/rssfeed_full.xml",           "SANS ISC Diary"),
    ("https://www.darkreading.com/rss.xml",             "Dark Reading"),
    ("https://www.securityweek.com/feed/",              "SecurityWeek"),
    ("https://threatpost.com/feed/",                    "Threatpost"),
    ("https://www.cisecurity.org/feed/advisories",      "CIS Advisories"),
]

# ════════════════════════════════════════════════════════════════════════════
#  @threat-intel — RSS feeds (deep threat intelligence)
# ════════════════════════════════════════════════════════════════════════════
THREAT_INTEL_FEEDS = [
    ("https://krebsonsecurity.com/feed/",               "Krebs on Security"),
    ("https://www.schneier.com/feed/atom/",             "Schneier on Security"),
    ("https://feeds.feedburner.com/eset/blog",          "ESET Research"),
    ("https://research.checkpoint.com/feed/",           "Check Point Research"),
    ("https://www.welivesecurity.com/feed/",            "WeLiveSecurity"),
]

# ════════════════════════════════════════════════════════════════════════════
#  #bug-bounty — Exploit-DB + HackerOne + writeup feeds
# ════════════════════════════════════════════════════════════════════════════
BUG_BOUNTY_FEEDS = [
    ("https://www.exploit-db.com/rss.xml",              "Exploit-DB"),
    ("https://hackerone.com/hacktivity.rss",            "HackerOne Hacktivity"),
    ("https://portswigger.net/blog/rss",                "PortSwigger Research"),
    ("https://bugs.chromium.org/feeds/chromium/issues.atom", "Chromium Bugs"),
    ("https://blog.intigriti.com/feed/", "Intigriti"),
    ("https://medium.com/feed/bugbountywriteup", "Medium BugBountyWriteup"),
]

def fetch_rss(feeds: list, webhook_key: str, color: str, hours: int = 24) -> list:
    """Generic RSS fetcher for a list of (url, label) tuples."""
    cutoff    = datetime.now(timezone.utc) - timedelta(hours=hours)
    all_items = []

    for feed_url, label in feeds:
        log.info("RSS: %s", label)
        try:
            feed  = feedparser.parse(feed_url)
            count = 0
            for entry in feed.entries[:8]:
                pub = entry.get("published_parsed") or entry.get("updated_parsed")
                if pub:
                    pub_dt = datetime(*pub[:6], tzinfo=timezone.utc)
                    if pub_dt < cutoff:
                        continue
                title   = entry.get("title", "No title")
                link    = entry.get("link", "")
                summary = entry.get("summary", entry.get("description", ""))
                if summary:
                    summary = BeautifulSoup(summary, "html.parser").get_text()
                    summary = summary[:350] + ("..." if len(summary) > 350 else "")
                all_items.append({
                    "id":      make_id(link or title),
                    "title":   f"[{label}] {title}",
                    "desc":    summary or "No summary.",
                    "url":     link,
                    "webhook": webhook_key,
                    "color":   color,
                    "mention": None,
                })
                count += 1
            log.info("  %s: %d items", label, count)
        except Exception as e:
            log.error("RSS failed %s: %s", label, e)

    return all_items


# ════════════════════════════════════════════════════════════════════════════
#  Web scraping helper — for sites with no RSS feed
# ════════════════════════════════════════════════════════════════════════════
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}

def scrape(url: str, article_sel: str, title_sel: str,
           link_sel: str, base_url: str, label: str,
           webhook_key: str, color: str) -> list:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.raise_for_status()
        soup  = BeautifulSoup(resp.text, "html.parser")
        items = []
        for article in soup.select(article_sel)[:6]:
            t_el = article.select_one(title_sel)
            l_el = article.select_one(link_sel)
            if not t_el:
                continue
            title = t_el.get_text(strip=True)
            href  = l_el.get("href", "") if l_el else ""
            if href and not href.startswith("http"):
                href = base_url.rstrip("/") + "/" + href.lstrip("/")
# ── Try to extract a real summary from the article card ──────────
            # Remove the title/link elements so they don't bleed into the summary
            for el in article.select(title_sel):
                el.decompose()
 
            summary = ""
            # 1. Look for explicit summary/excerpt elements first
            for sel in ("p", ".excerpt", ".summary", ".card-text",
                        ".entry-summary", ".post-excerpt", ".td-excerpt"):
                s_el = article.select_one(sel)
                if s_el:
                    summary = s_el.get_text(strip=True)
                    if len(summary) > 30:   # ignore tiny/empty paragraphs
                        break
 
            # 2. Fall back to all remaining text in the card
            if not summary:
                summary = article.get_text(separator=" ", strip=True)
 
            # 3. Clean up and trim
            summary = " ".join(summary.split())          # collapse whitespace
            summary = summary[:300] + ("..." if len(summary) > 300 else "")
 
            # 4. Last resort fallback
            if not summary or len(summary) < 10:
                summary = f"New post from **{label}**. Click to read the full article."
 
            items.append({
                "id":      make_id(href or title),
                "title":   f"[{label}] {title}",
                "desc":    summary,
                "url":     href,
                "webhook": webhook_key,
                "color":   color,
                "mention": None,
            })
        log.info("Scraped %s: %d items", label, len(items))
        return items
    except Exception as e:
        log.error("Scrape failed %s: %s", label, e)
        return []
# ════════════════════════════════════════════════════════════════════════════
#  #daily-news — Scraped daily news blogs (no RSS)
# ════════════════════════════════════════════════════════════════════════════
def fetch_daily_news_scraped() -> list:
    current_year = datetime.now().year
    items = []
    items += scrape(
        url = f"https://www.helpnetsecurity.com/{current_year}/",
        article_sel = "div.col",
        title_sel   = "h5.reset-heading, h5.card-title",
        link_sel    = "h5 a",
        base_url    = "https://www.helpnetsecurity.com",
        label       = "Help Net Security",
        webhook_key = "daily_news",
        color       = "news",
    )

    items += scrape(
        url         = "https://cybersecuritynews.com/",   
        article_sel = "div.td-module-container",          
        title_sel   = "h3.entry-title, h3.td-module-title",  
        link_sel    = "h3 a",                             
        base_url    = "https://cybersecuritynews.com",    
        label       = "Cyber Security News",
        webhook_key = "daily_news",
        color       = "news",
    )
    return items

# ════════════════════════════════════════════════════════════════════════════
#  @threat-intel — Scraped threat intel blogs (no RSS)
# ════════════════════════════════════════════════════════════════════════════
def fetch_threat_intel_scraped() -> list:
    items = []
    items += scrape(
        url="https://www.mandiant.com/resources/blog",
        article_sel=".blog-card, article, .resource-card",
        title_sel="h2, h3, .card-title",
        link_sel="a",
        base_url="https://www.mandiant.com",
        label="Mandiant Blog",
        webhook_key="threat_intel", color="intel",
    )
    items += scrape(
        url="https://unit42.paloaltonetworks.com/",
        article_sel="article, .entry-card",
        title_sel="h2, h3, .entry-title",
        link_sel="a",
        base_url="https://unit42.paloaltonetworks.com",
        label="Unit42 (Palo Alto)",
        webhook_key="threat_intel", color="intel",
    )
    items += scrape(
        url="https://www.recordedfuture.com/blog",
        article_sel="article, .blog-post, .post-card",
        title_sel="h2, h3, .post-title",
        link_sel="a",
        base_url="https://www.recordedfuture.com",
        label="Recorded Future",
        webhook_key="threat_intel", color="intel",
    )
    items += scrape(
        url="https://www.crowdstrike.com/blog/",
        article_sel="article, .blog-card",
        title_sel="h2, h3",
        link_sel="a",
        base_url="https://www.crowdstrike.com",
        label="CrowdStrike Blog",
        webhook_key="threat_intel", color="intel",
    )
    items += scrape(
        url="https://www.microsoft.com/en-us/security/blog/",
        article_sel="article, .card",
        title_sel="h3, h2",
        link_sel="a",
        base_url="https://www.microsoft.com",
        label="Microsoft Security",
        webhook_key="threat_intel", color="intel",
    )
    return items


# ════════════════════════════════════════════════════════════════════════════
#  #bug-bounty — Scraped bug bounty & vulnerability disclosure (no RSS)
# ════════════════════════════════════════════════════════════════════════════
def fetch_bug_bounty_scraped() -> list:
    items = []
    items += scrape(
        url="https://googleprojectzero.blogspot.com/",
        article_sel=".post",
        title_sel="h3.post-title, .post-title",
        link_sel="h3 a, .post-title a",
        base_url="",
        label="Google Project Zero",
        webhook_key="bug_bounty", color="bounty",
    )
    items += scrape(
        url="https://labs.watchtowr.com/",
        article_sel="article, .post",
        title_sel="h2, h3",
        link_sel="a",
        base_url="https://labs.watchtowr.com",
        label="watchTowr Labs",
        webhook_key="bug_bounty", color="bounty",
    )
    items += scrape(
        url="https://www.zerodayinitiative.com/blog/",
        article_sel="article, .blog-post",
        title_sel="h2, h3, .entry-title",
        link_sel="a",
        base_url="https://www.zerodayinitiative.com",
        label="Zero Day Initiative",
        webhook_key="bug_bounty", color="bounty",
    )
    return items


# ════════════════════════════════════════════════════════════════════════════
#  #tools-resources — GitHub trending security repos + ArXiv papers
# ════════════════════════════════════════════════════════════════════════════
GITHUB_TOPICS = [
    "cybersecurity", "penetration-testing", "osint",
    "bug-bounty", "malware-analysis", "red-team",
]

def fetch_github_tools(hours: int = 48) -> list:
    log.info("Fetching GitHub security tools...")
    since   = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d")
    token   = os.getenv("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    items      = []
    seen_repos = set()

    for topic in GITHUB_TOPICS[:4]:
        url = (
            f"https://api.github.com/search/repositories"
            f"?q=topic:{topic}+created:>{since}&sort=stars&order=desc&per_page=5"
        )
        try:
            data = requests.get(url, headers=headers, timeout=15).json()
            for repo in data.get("items", []):
                name = repo["full_name"]
                if name in seen_repos:
                    continue
                seen_repos.add(name)
                stars = repo.get("stargazers_count", 0)
                desc  = repo.get("description") or "No description."
                items.append({
                    "id":      make_id(name),
                    "title":   f"🛠️ New Tool: {name}  ⭐ {stars}",
                    "desc":    (
                        f"{desc[:300]}\n\n"
                        f"**Language:** {repo.get('language','N/A')}  "
                        f"**Stars:** {stars}  "
                        f"**Topic:** #{topic}"
                    ),
                    "url":     repo["html_url"],
                    "webhook": "tools_resources",
                    "color":   "tool",
                    "mention": None,
                })
            time.sleep(1)
        except Exception as e:
            log.error("GitHub topic %s failed: %s", topic, e)

    log.info("GitHub: %d new repos", len(items))
    return items

def fetch_arxiv_papers(hours: int = 24) -> list:
    """ArXiv cs.CR — latest security research papers."""
    log.info("Fetching ArXiv cs.CR papers...")
    try:
        feed  = feedparser.parse("https://export.arxiv.org/rss/cs.CR")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        items  = []
        for entry in feed.entries[:8]:
            pub = entry.get("published_parsed") or entry.get("updated_parsed")
            if pub:
                pub_dt = datetime(*pub[:6], tzinfo=timezone.utc)
                if pub_dt < cutoff:
                    continue
            summary = BeautifulSoup(entry.get("summary",""), "html.parser").get_text()
            items.append({
                "id":      make_id(entry.get("link","") or entry.get("title","")),
                "title":   f"📄 [ArXiv] {entry.get('title','No title')}",
                "desc":    summary[:400] + ("..." if len(summary) > 400 else ""),
                "url":     entry.get("link",""),
                "webhook": "tools_resources",
                "color":   "tool",
                "mention": None,
            })
        log.info("ArXiv: %d papers", len(items))
        return items
    except Exception as e:
        log.error("ArXiv failed: %s", e)
        return []


# ════════════════════════════════════════════════════════════════════════════
#  MAIN RUNNER
# ════════════════════════════════════════════════════════════════════════════
def run():
    log.info("=" * 60)
    log.info("CyberIntel Bot — %s UTC", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"))
    log.info("Channels: @threat-intel | #cve-updates | #bug-bounty | #daily-news | #tools-resources")
    log.info("=" * 60)

    cache = load_cache()
    sent  = 0
    skipped = 0

    all_items = []

# #cve-updates — NVD primary, fallbacks if NVD is down
    nvd_items = fetch_nvd_cves(min_cvss=7.0, hours=24)
    if nvd_items:
        all_items += nvd_items
        log.info("CVE source: NVD API (%d items)", len(nvd_items))
    else:
        log.warning("NVD returned nothing — switching to fallback CVE sources")
        all_items += fetch_cve_mitre_rss()
        all_items += fetch_vulndb_rss()
    all_items += fetch_cisa_kev(hours=24)
 
    # @threat-intel
    all_items += fetch_rss(THREAT_INTEL_FEEDS, "threat_intel", "intel", hours=24)
    all_items += fetch_threat_intel_scraped()
 
    # #bug-bounty
    all_items += fetch_rss(BUG_BOUNTY_FEEDS, "bug_bounty", "bounty", hours=24)
    all_items += fetch_bug_bounty_scraped()
 
    # #daily-news
    all_items += fetch_rss(DAILY_NEWS_FEEDS, "daily_news", "news", hours=24)
 
    # #tools-resources
    all_items += fetch_github_tools(hours=48)
    all_items += fetch_arxiv_papers(hours=24)
 
    log.info("Total collected: %d items", len(all_items))
 
    for item in all_items:
        if item["id"] in cache:
            skipped += 1
            continue
 
        ok = send_embed(
            webhook_key = item["webhook"],
            title       = item["title"],
            description = item["desc"],
            url         = item["url"],
            color_key   = item["color"],
            mention     = item.get("mention"),
        )
        if ok:
            cache.add(item["id"])
            sent += 1
            log.info("  ✓ %s", item["title"][:80])
            time.sleep(2)   # Discord rate limit safety
        else:
            log.warning("  ✗ Failed: %s", item["title"][:60])
 
    save_cache(cache)
    log.info("=" * 60)
    log.info("Done — Sent: %d  |  Already seen: %d", sent, skipped)
    log.info("=" * 60)
 
 
if __name__ == "__main__":
    run()
