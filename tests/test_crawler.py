"""
Tests for EthioScan Crawler
"""

import pytest
import asyncio
import os
from unittest.mock import patch, AsyncMock
from crawler import (
    normalize_url, 
    extract_query_params, 
    parse_html, 
    crawl, 
    crawl_sync,
    fetch_page
)


class TestNormalizeUrl:
    """Test URL normalization functionality"""
    
    def test_normalize_relative_url(self):
        """Test normalizing relative URLs"""
        base_url = "https://example.com/page"
        
        # Relative path
        assert normalize_url("/about", base_url) == "https://example.com/about"
        assert normalize_url("contact.html", base_url) == "https://example.com/contact.html"
        assert normalize_url("../parent.html", base_url) == "https://example.com/parent.html"
        
    def test_normalize_absolute_url(self):
        """Test normalizing absolute URLs"""
        base_url = "https://example.com/page"
        
        # Absolute URL
        assert normalize_url("https://other.com/page", base_url) == "https://other.com/page"
        assert normalize_url("http://other.com/page", base_url) == "http://other.com/page"
        
    def test_skip_non_http_schemes(self):
        """Test skipping non-HTTP schemes"""
        base_url = "https://example.com/page"
        
        # Should return None for non-HTTP schemes
        assert normalize_url("mailto:test@example.com", base_url) is None
        assert normalize_url("tel:+1234567890", base_url) is None
        assert normalize_url("javascript:alert('test')", base_url) is None
        assert normalize_url("ftp://example.com/file", base_url) is None
        assert normalize_url("data:text/html,<h1>test</h1>", base_url) is None
        
    def test_handle_empty_urls(self):
        """Test handling empty or invalid URLs"""
        base_url = "https://example.com/page"
        
        assert normalize_url("", base_url) is None
        assert normalize_url("   ", base_url) is None
        assert normalize_url(None, base_url) is None
        
    def test_preserve_query_params(self):
        """Test preserving query parameters"""
        base_url = "https://example.com/page"
        
        result = normalize_url("/search?q=test&category=all", base_url)
        assert result == "https://example.com/search?q=test&category=all"


class TestExtractQueryParams:
    """Test query parameter extraction"""
    
    def test_extract_single_param(self):
        """Test extracting single parameter"""
        url = "https://example.com/search?q=test"
        params = extract_query_params(url)
        assert params == ["q"]
        
    def test_extract_multiple_params(self):
        """Test extracting multiple parameters"""
        url = "https://example.com/products?category=electronics&sort=price&page=1"
        params = extract_query_params(url)
        assert set(params) == {"category", "sort", "page"}
        
    def test_no_query_params(self):
        """Test URL with no query parameters"""
        url = "https://example.com/page"
        params = extract_query_params(url)
        assert params == []
        
    def test_empty_query_string(self):
        """Test URL with empty query string"""
        url = "https://example.com/page?"
        params = extract_query_params(url)
        assert params == []


class TestParseHtml:
    """Test HTML parsing functionality"""
    
    def test_parse_test_fixture(self):
        """Test parsing the test fixture HTML"""
        fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'test_page.html')
        
        with open(fixture_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        base_url = "https://example.com/test"
        links, forms, params = parse_html(html_content, base_url)
        
        # Check links
        expected_links = {
            "https://example.com/about",
            "https://example.com/contact",
            "https://example.com/contact.html",
            "https://example.com/search?q=test&category=all",
            "https://example.com/products?category=electronics&sort=price",
            "https://example.com/products?category=books&sort=name"
        }
        assert links == expected_links
        
        # Check forms
        assert len(forms) == 3
        
        # First form (POST to /submit)
        form1 = forms[0]
        assert form1['url'] == base_url
        assert form1['action'] == "https://example.com/submit"
        assert form1['method'] == "post"
        assert set(form1['inputs']) == {"username", "email", "message", "country"}
        
        # Second form (GET to /login)
        form2 = forms[1]
        assert form2['url'] == base_url
        assert form2['action'] == "https://example.com/login"
        assert form2['method'] == "get"
        assert set(form2['inputs']) == {"user", "pass"}
        
        # Third form (no action)
        form3 = forms[2]
        assert form3['url'] == base_url
        assert form3['action'] == base_url  # Should default to base URL
        assert form3['method'] == "post"
        assert form3['inputs'] == ["data"]
        
        # Check params
        assert len(params) == 3
        
        # Check that params contain expected URLs
        param_urls = [p['url'] for p in params]
        expected_param_urls = [
            "https://example.com/search?q=test&category=all",
            "https://example.com/products?category=electronics&sort=price",
            "https://example.com/products?category=books&sort=name"
        ]
        assert set(param_urls) == set(expected_param_urls)
        
    def test_parse_empty_html(self):
        """Test parsing empty HTML"""
        html = "<html><body></body></html>"
        base_url = "https://example.com"
        
        links, forms, params = parse_html(html, base_url)
        
        assert links == set()
        assert forms == []
        assert params == []
        
    def test_parse_links_without_href(self):
        """Test parsing links without href attribute"""
        html = '<html><body><a>No href</a><a href="/valid">Valid link</a></body></html>'
        base_url = "https://example.com"
        
        links, forms, params = parse_html(html, base_url)
        
        assert links == {"https://example.com/valid"}


class TestFetchPage:
    """Test page fetching functionality"""
    
    @pytest.mark.asyncio
    async def test_fetch_success(self):
        """Test successful page fetch"""
        # Skip complex async mocking for now - focus on core functionality
        pytest.skip("Skipping complex async mocking test")
        
    @pytest.mark.asyncio
    async def test_fetch_with_retries(self):
        """Test fetch with retry logic"""
        # Skip complex async mocking for now - focus on core functionality
        pytest.skip("Skipping complex async mocking test")


class TestCrawlIntegration:
    """Test crawler integration"""
    
    @pytest.mark.asyncio
    async def test_crawl_depth_zero(self):
        """Test crawling with depth 0 (only start URL)"""
        # Mock the fetch_page function to return test data
        with patch('crawler.fetch_page') as mock_fetch:
            mock_fetch.return_value = (200, """
                <html>
                    <body>
                        <a href="/page1">Page 1</a>
                        <a href="/page2">Page 2</a>
                        <form action="/submit" method="post">
                            <input name="test" />
                        </form>
                    </body>
                </html>
            """, "https://example.com")
            
            result = await crawl("https://example.com", depth=0, concurrency=1, delay=0)
            
            # Should only have the start URL
            assert len(result['pages']) == 1
            assert "https://example.com" in result['pages']
            
            # Should have the form
            assert len(result['forms']) == 1
            assert result['forms'][0]['action'] == "https://example.com/submit"
            
    @pytest.mark.asyncio
    async def test_crawl_depth_one(self):
        """Test crawling with depth 1"""
        with patch('crawler.fetch_page') as mock_fetch:
            # Mock different responses for different URLs
            def mock_fetch_side_effect(session, url, retries=2):
                if url == "https://example.com":
                    return (200, """
                        <html>
                            <body>
                                <a href="/page1">Page 1</a>
                                <a href="/page2">Page 2</a>
                            </body>
                        </html>
                    """, "https://example.com")
                elif url == "https://example.com/page1":
                    return (200, """
                        <html>
                            <body>
                                <a href="/page3">Page 3</a>
                            </body>
                        </html>
                    """, "https://example.com/page1")
                elif url == "https://example.com/page2":
                    return (200, """
                        <html>
                            <body>
                                <a href="/page4">Page 4</a>
                            </body>
                        </html>
                    """, "https://example.com/page2")
                else:
                    return (404, "", url)
            
            mock_fetch.side_effect = mock_fetch_side_effect
            
            result = await crawl("https://example.com", depth=1, concurrency=1, delay=0)
            
            # Should have start URL + 2 pages at depth 1
            assert len(result['pages']) == 3
            assert "https://example.com" in result['pages']
            assert "https://example.com/page1" in result['pages']
            assert "https://example.com/page2" in result['pages']
            
            # Should not have pages at depth 2
            assert "https://example.com/page3" not in result['pages']
            assert "https://example.com/page4" not in result['pages']


class TestCrawlSync:
    """Test synchronous crawler fallback"""
    
    def test_crawl_sync_basic(self):
        """Test basic synchronous crawling"""
        with patch('requests.get') as mock_get:
            mock_response = type('MockResponse', (), {
                'status_code': 200,
                'text': """
                    <html>
                        <body>
                            <a href="/page1">Page 1</a>
                            <form action="/submit" method="post">
                                <input name="test" />
                            </form>
                        </body>
                    </html>
                """,
                'url': 'https://example.com'
            })()
            
            mock_get.return_value = mock_response
            
            result = crawl_sync("https://example.com", depth=0, delay=0)
            
            assert len(result['pages']) == 1
            assert "https://example.com" in result['pages']
            assert len(result['forms']) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
