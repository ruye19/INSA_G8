"""
EthioScan Crawler - Async web crawler for discovering pages, forms, and parameters
"""

import asyncio
import time
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from urllib.robotparser import RobotFileParser
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
                'User-Agent': 'EthioScan/1.0 (Ethiopian Security Scanner)'
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
    
    Args:
        url: URL to normalize (can be relative)
        base_url: Base URL for resolving relative URLs
        
    Returns:
        Normalized absolute URL or None if invalid
    """
    try:
        # Handle empty or None URLs
        if not url or url.strip() == '':
            return None
            
        # Skip non-HTTP schemes
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in ['http', 'https']:
            return None
            
        # Skip mailto, tel, javascript, etc.
        if parsed.scheme in ['mailto', 'tel', 'javascript', 'data', 'ftp']:
            return None
            
        # Make absolute URL
        absolute_url = urljoin(base_url, url)
        parsed_absolute = urlparse(absolute_url)
        
        # Ensure we have a valid scheme and netloc
        if not parsed_absolute.scheme or not parsed_absolute.netloc:
            return None
            
        # Remove fragment
        normalized = f"{parsed_absolute.scheme}://{parsed_absolute.netloc}{parsed_absolute.path}"
        if parsed_absolute.query:
            normalized += f"?{parsed_absolute.query}"
            
        return normalized
        
    except Exception:
        return None


def extract_query_params(url: str) -> List[str]:
    """
    Extract query parameter names from a URL.
    
    Args:
        url: URL to extract parameters from
        
    Returns:
        List of parameter names
    """
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
    Fetch a page with retry logic and exponential backoff.
    
    Args:
        session: aiohttp session
        url: URL to fetch
        retries: Number of retries on failure
        
    Returns:
        Tuple of (status_code, content, final_url)
    """
    for attempt in range(retries + 1):
        try:
            async with session.get(url, allow_redirects=True) as response:
                content = await response.text()
                return response.status, content, str(response.url)
        except Exception as e:
            if attempt < retries:
                # Exponential backoff
                delay = 2 ** attempt
                console.print(f"[yellow]Retrying {url} in {delay}s (attempt {attempt + 1}/{retries + 1})[/yellow]")
                await asyncio.sleep(delay)
            else:
                console.print(f"[red]Failed to fetch {url}: {e}[/red]")
                return 0, "", url


def parse_html(html: str, base_url: str) -> Tuple[Set[str], List[Dict], List[Dict]]:
    """
    Parse HTML content to extract links, forms, and parameters.
    
    Args:
        html: HTML content
        base_url: Base URL for resolving relative URLs
        
    Returns:
        Tuple of (links_set, forms_list, params_list)
    """
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    forms = []
    params = []
    
    # Extract links
    for a_tag in soup.find_all('a', href=True):
        normalized_url = normalize_url(a_tag['href'], base_url)
        if normalized_url:
            links.add(normalized_url)
            # Extract query parameters
            query_params = extract_query_params(normalized_url)
            if query_params:
                params.append({
                    'url': normalized_url,
                    'params': query_params
                })
    
    # Extract forms
    for form in soup.find_all('form'):
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        # Normalize action URL
        action_url = urljoin(base_url, action) if action else base_url
        
        # Extract input names
        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                inputs.append(name)
        
        forms.append({
            'url': base_url,
            'action': action_url,
            'method': method,
            'inputs': inputs
        })
    
    return links, forms, params


async def crawl(start_url: str, depth: int = 2, concurrency: int = 5, delay: float = 0.2) -> Dict:
    """
    Crawl start_url up to specified depth.
    
    Args:
        start_url: Starting URL to crawl
        depth: Maximum crawling depth
        concurrency: Number of concurrent requests
        delay: Delay between requests (seconds)
        
    Returns:
        Dictionary with pages, forms, and params
    """
    start_time = time.time()
    console.print(f"[EthioScan] Crawling {start_url} (depth {depth})")
    
    # Initialize crawler
    async with Crawler(concurrency=concurrency, delay=delay) as crawler:
        visited_urls: Set[str] = set()
        all_pages: Set[str] = set()
        all_forms: List[Dict] = []
        all_params: List[Dict] = []
        
        # Queue for BFS crawling
        url_queue = [(start_url, 0)]  # (url, current_depth)
        
        while url_queue:
            # Get URLs for current depth level
            current_depth_urls = [(url, depth_level) for url, depth_level in url_queue if depth_level <= depth]
            url_queue = [(url, depth_level) for url, depth_level in url_queue if depth_level > depth]
            
            if not current_depth_urls:
                break
                
            # Process URLs at current depth
            tasks = []
            for url, current_depth in current_depth_urls:
                if url not in visited_urls and current_depth <= depth:
                    visited_urls.add(url)
                    task = crawler.semaphore.acquire()
                    tasks.append((task, url, current_depth))
            
            # Execute tasks
            for task, url, current_depth in tasks:
                await task
                try:
                    status, content, final_url = await fetch_page(crawler.session, url)
                    
                    if status == 200 and content:
                        all_pages.add(final_url)
                        
                        # Parse HTML
                        links, forms, params = parse_html(content, final_url)
                        
                        # Add forms and params
                        all_forms.extend(forms)
                        all_params.extend(params)
                        
                        # Add new URLs to queue for next depth
                        if current_depth < depth:
                            for link in links:
                                if link not in visited_urls:
                                    url_queue.append((link, current_depth + 1))
                    
                    # Polite delay
                    await asyncio.sleep(delay)
                    
                except Exception as e:
                    console.print(f"[red]Error processing {url}: {e}[/red]")
                finally:
                    crawler.semaphore.release()
    
    # Deduplicate results
    unique_forms = []
    seen_forms = set()
    for form in all_forms:
        form_key = (form['url'], form['action'], form['method'])
        if form_key not in seen_forms:
            seen_forms.add(form_key)
            unique_forms.append(form)
    
    unique_params = []
    seen_params = set()
    for param in all_params:
        param_key = param['url']
        if param_key not in seen_params:
            seen_params.add(param_key)
            unique_params.append(param)
    
    elapsed = time.time() - start_time
    console.print(f"[EthioScan] Discovered {len(all_pages)} pages, {len(unique_forms)} forms, {len(unique_params)} paramized URLs")
    console.print(f"[EthioScan] Done crawling (elapsed {elapsed:.1f}s)")
    
    return {
        'pages': sorted(list(all_pages)),
        'forms': unique_forms,
        'params': unique_params
    }


# Synchronous fallback using requests
def crawl_sync(start_url: str, depth: int = 2, concurrency: int = 5, delay: float = 0.2) -> Dict:
    """
    Synchronous fallback crawler using requests library.
    
    Args:
        start_url: Starting URL to crawl
        depth: Maximum crawling depth
        concurrency: Number of concurrent requests (ignored in sync version)
        delay: Delay between requests (seconds)
        
    Returns:
        Dictionary with pages, forms, and params
    """
    console.print("[yellow]Using synchronous crawler (aiohttp not available)[/yellow]")
    
    start_time = time.time()
    console.print(f"[EthioScan] Crawling {start_url} (depth {depth})")
    
    visited_urls: Set[str] = set()
    all_pages: Set[str] = set()
    all_forms: List[Dict] = []
    all_params: List[Dict] = []
    
    url_queue = [(start_url, 0)]
    
    while url_queue:
        current_depth_urls = [(url, depth_level) for url, depth_level in url_queue if depth_level <= depth]
        url_queue = [(url, depth_level) for url, depth_level in url_queue if depth_level > depth]
        
        if not current_depth_urls:
            break
            
        for url, current_depth in current_depth_urls:
            if url not in visited_urls and current_depth <= depth:
                visited_urls.add(url)
                
                try:
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    if response.status_code == 200:
                        all_pages.add(response.url)
                        
                        # Parse HTML
                        links, forms, params = parse_html(response.text, response.url)
                        
                        # Add forms and params
                        all_forms.extend(forms)
                        all_params.extend(params)
                        
                        # Add new URLs to queue for next depth
                        if current_depth < depth:
                            for link in links:
                                if link not in visited_urls:
                                    url_queue.append((link, current_depth + 1))
                    
                    # Polite delay
                    time.sleep(delay)
                    
                except Exception as e:
                    console.print(f"[red]Error processing {url}: {e}[/red]")
    
    # Deduplicate results (same as async version)
    unique_forms = []
    seen_forms = set()
    for form in all_forms:
        form_key = (form['url'], form['action'], form['method'])
        if form_key not in seen_forms:
            seen_forms.add(form_key)
            unique_forms.append(form)
    
    unique_params = []
    seen_params = set()
    for param in all_params:
        param_key = param['url']
        if param_key not in seen_params:
            seen_params.add(param_key)
            unique_params.append(param)
    
    elapsed = time.time() - start_time
    console.print(f"[EthioScan] Discovered {len(all_pages)} pages, {len(unique_forms)} forms, {len(unique_params)} paramized URLs")
    console.print(f"[EthioScan] Done crawling (elapsed {elapsed:.1f}s)")
    
    return {
        'pages': sorted(list(all_pages)),
        'forms': unique_forms,
        'params': unique_params
    }
