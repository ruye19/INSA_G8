"""
EthioScan Crawler - Async web crawler for discovering pages, forms, and parameters
Improved: accepts POST forms, normalizes absolute/relative action URLs,
and logs discovered forms/params for easier debugging.
"""

import asyncio
import time
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import aiohttp
import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()


class Crawler:
    """Async web crawler for EthioScan"""

    def __init__(self, concurrency: int = 5, delay: float = 0.2, timeout: int = 10):
        self.concurrency = concurrency
        self.delay = delay
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": "EthioScan/1.0 (Ethiopian Security Scanner)"
            }
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()


def normalize_url(url: str, base_url: str) -> Optional[str]:
    """
    Normalize a URL to absolute form.

    Returns normalized absolute URL or None if invalid / non-http(s).
    """
    try:
        if not url or url.strip() == "":
            return None

        # Resolve with base
        absolute = urljoin(base_url, url)
        parsed = urlparse(absolute)

        # Only http/https are supported
        if parsed.scheme not in ("http", "https"):
            return None

        # Build normalized URL (preserve path + query)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    except Exception:
        return None


def extract_query_params(url: str) -> List[str]:
    """Return list of parameter names extracted from the URL's query string."""
    try:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            return list(params.keys())
        return []
    except Exception:
        return []


async def fetch_page(session: aiohttp.ClientSession, url: str, retries: int = 2) -> Tuple[int, str, str]:
    """
    Fetch a page with retry and exponential backoff.
    Returns (status_code, content_text, final_url).
    """
    for attempt in range(retries + 1):
        try:
            async with session.get(url, allow_redirects=True) as response:
                content = await response.text()
                return response.status, content, str(response.url)
        except Exception as e:
            if attempt < retries:
                backoff = 2 ** attempt
                console.print(f"[yellow]Retrying {url} in {backoff}s (attempt {attempt + 1})[/yellow]")
                await asyncio.sleep(backoff)
            else:
                console.print(f"[red]Failed to fetch {url}: {e}[/red]")
                return 0, "", url


def parse_html(html: str, base_url: str) -> Tuple[Set[str], List[Dict], List[Dict]]:
    """
    Parse HTML content to extract links, forms, and params.
    Returns (links_set, forms_list, params_list).
    """
    soup = BeautifulSoup(html, "html.parser")
    links: Set[str] = set()
    forms: List[Dict] = []
    params: List[Dict] = []

    # Extract links (<a href>)
    for a_tag in soup.find_all("a", href=True):
        normalized = normalize_url(a_tag["href"], base_url)
        if normalized:
            links.add(normalized)
            qnames = extract_query_params(normalized)
            if qnames:
                params.append({"url": normalized, "params": qnames})

    # Extract forms
    for form in soup.find_all("form"):
        raw_action = form.get("action", "")
        raw_method = form.get("method", "get").lower().strip()

        # Normalize action to absolute URL (use base_url when action is empty)
        action_url = normalize_url(raw_action, base_url) if raw_action else normalize_url(base_url, base_url)

        # If normalize_url returned None (e.g., javascript:), fallback to base_url
        if not action_url:
            action_url = normalize_url(base_url, base_url)

        # Collect input/textarea/select names
        inputs: List[str] = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append(name)

        # Only accept common methods: get & post (avoid weird ones by default)
        method = raw_method if raw_method in ("get", "post") else "get"

        form_entry = {
            "url": normalize_url(base_url, base_url) or base_url,
            "action": action_url,
            "method": method,
            "inputs": inputs,
        }

        forms.append(form_entry)

        # If the action URL has query params, register them as parameterized URLs
        qnames = extract_query_params(action_url)
        if qnames:
            params.append({"url": action_url, "params": qnames})

        # Debug print for easier troubleshooting during development
        console.print(f"[debug] Found form -> action: {action_url} method: {method} inputs: {inputs}")

    return links, forms, params


async def crawl(start_url: str, depth: int = 2, concurrency: int = 5, delay: float = 0.2) -> Dict:
    """
    Crawl start_url up to specified depth and return discovered pages, forms, params.
    """
    start_time = time.time()
    console.print(f"[EthioScan] Crawling {start_url} (depth {depth})")

    async with Crawler(concurrency=concurrency, delay=delay) as crawler:
        visited_urls: Set[str] = set()
        all_pages: Set[str] = set()
        all_forms: List[Dict] = []
        all_params: List[Dict] = []

        # BFS queue: (url, depth_level)
        url_queue: List[Tuple[str, int]] = [(start_url, 0)]

        while url_queue:
            # Get items within allowed depth
            current_level = [(u, d) for u, d in url_queue if d <= depth]
            url_queue = [(u, d) for u, d in url_queue if d > depth]

            if not current_level:
                break

            tasks = []
            for url, cur_depth in current_level:
                if url not in visited_urls and cur_depth <= depth:
                    visited_urls.add(url)
                    tasks.append((await crawler.semaphore.acquire(), url, cur_depth))

            # Execute sequentially but respect concurrency by semaphore acquisitions
            for sem_acq, url, cur_depth in tasks:
                try:
                    status, content, final_url = await fetch_page(crawler.session, url)

                    # Consider a page as discovered if we got meaningful content (status 200 or any HTML)
                    if status and content:
                        # Normalize final_url
                        normalized_final = normalize_url(final_url, final_url) or final_url
                        all_pages.add(normalized_final)

                        links, forms, params = parse_html(content, normalized_final)
                        all_forms.extend(forms)
                        all_params.extend(params)

                        if cur_depth < depth:
                            for link in links:
                                if link not in visited_urls:
                                    url_queue.append((link, cur_depth + 1))

                    # Polite delay between requests
                    await asyncio.sleep(delay)

                except Exception as e:
                    console.print(f"[red]Error processing {url}: {e}[/red]")
                finally:
                    crawler.semaphore.release()

    # Deduplicate forms (url, action, method)
    unique_forms: List[Dict] = []
    seen_forms = set()
    for f in all_forms:
        key = (f.get("url"), f.get("action"), f.get("method"))
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(f)

    # Deduplicate params by URL
    unique_params: List[Dict] = []
    seen_params = set()
    for p in all_params:
        key = p.get("url")
        if key and key not in seen_params:
            seen_params.add(key)
            unique_params.append(p)

    elapsed = time.time() - start_time
    console.print(f"[EthioScan] Discovered {len(all_pages)} pages, {len(unique_forms)} forms, {len(unique_params)} paramized URLs")
    console.print(f"[EthioScan] Done crawling (elapsed {elapsed:.1f}s)")

    return {"pages": sorted(list(all_pages)), "forms": unique_forms, "params": unique_params}


# Synchronous fallback using requests
def crawl_sync(start_url: str, depth: int = 2, concurrency: int = 5, delay: float = 0.2) -> Dict:
    console.print("[yellow]Using synchronous crawler (aiohttp not available)[/yellow]")

    start_time = time.time()
    console.print(f"[EthioScan] Crawling {start_url} (depth {depth})")

    visited_urls: Set[str] = set()
    all_pages: Set[str] = set()
    all_forms: List[Dict] = []
    all_params: List[Dict] = []

    url_queue: List[Tuple[str, int]] = [(start_url, 0)]

    while url_queue:
        current_level = [(u, d) for u, d in url_queue if d <= depth]
        url_queue = [(u, d) for u, d in url_queue if d > depth]

        if not current_level:
            break

        for url, cur_depth in current_level:
            if url not in visited_urls and cur_depth <= depth:
                visited_urls.add(url)
                try:
                    resp = requests.get(url, timeout=10, allow_redirects=True)
                    if resp.status_code and resp.text:
                        normalized_final = normalize_url(resp.url, resp.url) or resp.url
                        all_pages.add(normalized_final)

                        links, forms, params = parse_html(resp.text, normalized_final)
                        all_forms.extend(forms)
                        all_params.extend(params)

                        if cur_depth < depth:
                            for link in links:
                                if link not in visited_urls:
                                    url_queue.append((link, cur_depth + 1))

                    time.sleep(delay)

                except Exception as e:
                    console.print(f"[red]Error processing {url}: {e}[/red]")

    # Deduplicate as above
    unique_forms: List[Dict] = []
    seen_forms = set()
    for f in all_forms:
        key = (f.get("url"), f.get("action"), f.get("method"))
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(f)

    unique_params: List[Dict] = []
    seen_params = set()
    for p in all_params:
        key = p.get("url")
        if key and key not in seen_params:
            seen_params.add(key)
            unique_params.append(p)

    elapsed = time.time() - start_time
    console.print(f"[EthioScan] Discovered {len(all_pages)} pages, {len(unique_forms)} forms, {len(unique_params)} paramized URLs")
    console.print(f"[EthioScan] Done crawling (elapsed {elapsed:.1f}s)")

    return {"pages": sorted(list(all_pages)), "forms": unique_forms, "params": unique_params}
