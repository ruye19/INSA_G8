"""
EthioScan Fuzzer - Test case generation and submission for vulnerability scanning
"""

import uuid
import time
import asyncio
from typing import Dict, List, Any, Iterable, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
import requests
from ethioscan.payloads import get_payloads, is_lab_only_payload


def generate_tests_from_params(params: List[Dict], payloads: Dict, max_per_param: int = 3) -> Iterable[Dict]:
    """
    Generate test cases from discovered URL parameters.
    
    Args:
        params: List of parameter dictionaries from crawler
        payloads: Payload dictionary from get_payloads()
        max_per_param: Maximum number of payloads per parameter
        
    Yields:
        Test case dictionaries with id, method, url, param, payload, etc.
    """
    for param_item in params:
        url = param_item["url"]
        param_names = param_item["params"]
        
        # Parse the original URL to preserve other parameters
        parsed_url = urlparse(url)
        original_params = parse_qs(parsed_url.query)
        
        for param_name in param_names:
            # Generate tests for each payload category
            for category, payload_list in payloads.items():
                # Skip IDOR numeric for non-numeric parameters (basic heuristic)
                if category == "idor_numeric" and not _is_numeric_param(param_name):
                    continue
                
                # Limit payloads per parameter
                limited_payloads = payload_list[:max_per_param]
                
                for payload_item in limited_payloads:
                    # Create test case
                    test_case = {
                        "id": str(uuid.uuid4()),
                        "method": "GET",
                        "url": _build_test_url(url, param_name, payload_item, category),
                        "param": param_name,
                        "payload": payload_item,
                        "origin": "param",
                        "meta": {
                            "category": category,
                            "lab_only": is_lab_only_payload(category, payload_item)
                        },
                        "crawl_ref": param_item
                    }
                    
                    yield test_case


def generate_tests_from_forms(forms: List[Dict], payloads: Dict, max_samples: int = 3) -> Iterable[Dict]:
    """
    Generate test cases from discovered forms.
    
    Args:
        forms: List of form dictionaries from crawler
        payloads: Payload dictionary from get_payloads()
        max_samples: Maximum number of payload samples per form input
        
    Yields:
        Test case dictionaries with form-specific fields
    """
    for form in forms:
        form_url = form["url"]
        form_action = form["action"]
        form_method = form["method"].upper()
        form_inputs = form["inputs"]
        
        # Generate tests for each input field
        for input_name in form_inputs:
            # Generate tests for each payload category
            for category, payload_list in payloads.items():
                # Skip IDOR numeric for form inputs (not applicable)
                if category == "idor_numeric":
                    continue
                
                # Limit payloads per input
                limited_payloads = payload_list[:max_samples]
                
                for payload_item in limited_payloads:
                    # Create test case
                    test_case = {
                        "id": str(uuid.uuid4()),
                        "method": form_method,
                        "url": form_action,
                        "param": input_name,
                        "payload": payload_item,
                        "origin": "form",
                        "meta": {
                            "category": category,
                            "lab_only": is_lab_only_payload(category, payload_item)
                        },
                        "crawl_ref": form,
                        "form_action": form_action,
                        "form_inputs": form_inputs
                    }
                    
                    yield test_case


def generate_curl_command(test_case: Dict) -> str:
    """
    Convert a test case to a curl command string.
    
    Args:
        test_case: Test case dictionary
        
    Returns:
        Escaped curl command string
    """
    method = test_case["method"]
    url = test_case["url"]
    param = test_case["param"]
    payload = test_case["payload"]
    
    # Build curl command
    curl_parts = ["curl", "-X", method]
    
    if method == "POST":
        # For POST requests, add form data
        if "form_inputs" in test_case:
            # Build form data with payload in target field and benign values in others
            form_data = {}
            for input_name in test_case["form_inputs"]:
                if input_name == param:
                    # Insert payload
                    if isinstance(payload, dict) and "payload" in payload:
                        form_data[input_name] = payload["payload"]
                    else:
                        form_data[input_name] = str(payload)
                else:
                    # Use benign value
                    form_data[input_name] = "test_value"
            
            # Add form data
            curl_parts.extend(["-d", urlencode(form_data)])
        else:
            # Simple POST with single parameter
            if isinstance(payload, dict) and "payload" in payload:
                payload_value = payload["payload"]
            else:
                payload_value = str(payload)
            
            curl_parts.extend(["-d", f"{param}={urlencode({'': payload_value})[2:]}"])
    else:
        # For GET requests, URL should already contain the payload
        pass
    
    # Add URL
    curl_parts.append(f'"{url}"')
    
    # Add headers
    curl_parts.extend(["-H", '"User-Agent: EthioScan/1.0"'])
    curl_parts.extend(["-H", '"Accept: text/html,application/xhtml+xml"'])
    
    return " ".join(curl_parts)


async def submit_test_case(session: aiohttp.ClientSession, test_case: Dict, timeout: int = 10) -> Dict:
    """
    Submit a test case using async HTTP session.
    
    Args:
        session: aiohttp ClientSession
        test_case: Test case dictionary
        timeout: Request timeout in seconds
        
    Returns:
        Response dictionary with status, headers, body, final_url, elapsed
    """
    start_time = time.time()
    
    try:
        if test_case["method"] == "POST":
            # Handle POST request
            if "form_inputs" in test_case:
                # Build form data
                form_data = {}
                for input_name in test_case["form_inputs"]:
                    if input_name == test_case["param"]:
                        # Insert payload
                        if isinstance(test_case["payload"], dict) and "payload" in test_case["payload"]:
                            form_data[input_name] = test_case["payload"]["payload"]
                        else:
                            form_data[input_name] = str(test_case["payload"])
                    else:
                        # Use benign value
                        form_data[input_name] = "test_value"
                
                async with session.post(
                    test_case["url"],
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True
                ) as response:
                    body = await response.text()
                    elapsed = time.time() - start_time
                    
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": body,
                        "final_url": str(response.url),
                        "elapsed": elapsed
                    }
            else:
                # Simple POST
                if isinstance(test_case["payload"], dict) and "payload" in test_case["payload"]:
                    payload_value = test_case["payload"]["payload"]
                else:
                    payload_value = str(test_case["payload"])
                
                form_data = {test_case["param"]: payload_value}
                
                async with session.post(
                    test_case["url"],
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True
                ) as response:
                    body = await response.text()
                    elapsed = time.time() - start_time
                    
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": body,
                        "final_url": str(response.url),
                        "elapsed": elapsed
                    }
        else:
            # Handle GET request
            async with session.get(
                test_case["url"],
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True
            ) as response:
                body = await response.text()
                elapsed = time.time() - start_time
                
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "final_url": str(response.url),
                    "elapsed": elapsed
                }
                
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "final_url": test_case["url"],
            "elapsed": elapsed,
            "error": str(e)
        }


def submit_test_case_sync(test_case: Dict, timeout: int = 10) -> Dict:
    """
    Submit a test case using synchronous requests (fallback).
    
    Args:
        test_case: Test case dictionary
        timeout: Request timeout in seconds
        
    Returns:
        Response dictionary with status, headers, body, final_url, elapsed
    """
    start_time = time.time()
    
    try:
        headers = {
            'User-Agent': 'EthioScan/1.0 (Ethiopian Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml'
        }
        
        if test_case["method"] == "POST":
            # Handle POST request
            if "form_inputs" in test_case:
                # Build form data
                form_data = {}
                for input_name in test_case["form_inputs"]:
                    if input_name == test_case["param"]:
                        # Insert payload
                        if isinstance(test_case["payload"], dict) and "payload" in test_case["payload"]:
                            form_data[input_name] = test_case["payload"]["payload"]
                        else:
                            form_data[input_name] = str(test_case["payload"])
                    else:
                        # Use benign value
                        form_data[input_name] = "test_value"
                
                response = requests.post(
                    test_case["url"],
                    data=form_data,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True
                )
            else:
                # Simple POST
                if isinstance(test_case["payload"], dict) and "payload" in test_case["payload"]:
                    payload_value = test_case["payload"]["payload"]
                else:
                    payload_value = str(test_case["payload"])
                
                form_data = {test_case["param"]: payload_value}
                
                response = requests.post(
                    test_case["url"],
                    data=form_data,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True
                )
        else:
            # Handle GET request
            response = requests.get(
                test_case["url"],
                headers=headers,
                timeout=timeout,
                allow_redirects=True
            )
        
        elapsed = time.time() - start_time
        
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "final_url": response.url,
            "elapsed": elapsed
        }
        
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "final_url": test_case["url"],
            "elapsed": elapsed,
            "error": str(e)
        }


async def quick_precheck(session: aiohttp.ClientSession, test_case: Dict, timeout: int = 5) -> Dict:
    """
    Perform a quick preliminary check to detect obvious payload reflection or errors.
    
    Args:
        session: aiohttp ClientSession
        test_case: Test case dictionary
        timeout: Request timeout in seconds
        
    Returns:
        Preliminary check results with flags
    """
    try:
        response = await submit_test_case(session, test_case, timeout)
        
        # Check for payload reflection
        payload_str = ""
        if isinstance(test_case["payload"], dict) and "payload" in test_case["payload"]:
            payload_str = test_case["payload"]["payload"]
        else:
            payload_str = str(test_case["payload"])
        
        body = response.get("body", "").lower()
        payload_lower = payload_str.lower()
        
        # Check for reflection
        payload_reflected = payload_lower in body
        
        # Check for common error patterns
        sql_errors = any(error in body for error in [
            "sql syntax", "mysql", "postgresql", "oracle", "sqlite",
            "database error", "sql error", "query failed"
        ])
        
        xss_reflected = any(tag in body for tag in [
            "<script>", "<img", "<svg", "<iframe", "<body"
        ]) and payload_reflected
        
        return {
            "payload_reflected": payload_reflected,
            "sql_errors": sql_errors,
            "xss_reflected": xss_reflected,
            "status_code": response.get("status", 0),
            "response_time": response.get("elapsed", 0)
        }
        
    except Exception as e:
        return {
            "payload_reflected": False,
            "sql_errors": False,
            "xss_reflected": False,
            "status_code": 0,
            "response_time": 0,
            "error": str(e)
        }


def _build_test_url(original_url: str, param_name: str, payload_item: Dict, category: str) -> str:
    """
    Build a test URL with the payload injected into the specified parameter.
    
    Args:
        original_url: Original URL from crawler
        param_name: Parameter name to inject payload into
        payload_item: Payload dictionary
        category: Payload category
        
    Returns:
        Modified URL with payload injected
    """
    parsed_url = urlparse(original_url)
    original_params = parse_qs(parsed_url.query)
    
    # Get payload value
    if category == "idor_numeric":
        # Handle IDOR numeric payloads specially
        if payload_item["kind"] == "adjacent":
            # Try to extract numeric value from original parameter
            original_value = original_params.get(param_name, ["1"])[0]
            try:
                numeric_value = int(original_value) + payload_item["delta"]
                payload_value = str(numeric_value)
            except (ValueError, TypeError):
                payload_value = str(payload_item["delta"])
        else:
            payload_value = str(payload_item["value"])
    else:
        # Regular payload
        if "payload" in payload_item:
            payload_value = payload_item["payload"]
        else:
            payload_value = str(payload_item)
    
    # Update the parameter
    original_params[param_name] = [payload_value]
    
    # Rebuild URL
    new_query = urlencode(original_params, doseq=True)
    new_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment
    ))
    
    return new_url


def _is_numeric_param(param_name: str) -> bool:
    """
    Basic heuristic to determine if a parameter is likely numeric.
    
    Args:
        param_name: Parameter name
        
    Returns:
        True if parameter appears to be numeric
    """
    numeric_indicators = [
        "id", "page", "offset", "limit", "count", "num", "index",
        "user_id", "item_id", "product_id", "order_id"
    ]
    
    param_lower = param_name.lower()
    return any(indicator in param_lower for indicator in numeric_indicators)


def get_test_case_summary(test_cases: List[Dict]) -> Dict[str, int]:
    """
    Get summary statistics for generated test cases.
    
    Args:
        test_cases: List of test case dictionaries
        
    Returns:
        Summary dictionary with counts by category and origin
    """
    summary = {
        "total": len(test_cases),
        "by_category": {},
        "by_origin": {"param": 0, "form": 0},
        "lab_only": 0
    }
    
    for test_case in test_cases:
        # Count by category
        category = test_case["meta"]["category"]
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        
        # Count by origin
        origin = test_case["origin"]
        summary["by_origin"][origin] += 1
        
        # Count lab-only
        if test_case["meta"]["lab_only"]:
            summary["lab_only"] += 1
    
    return summary
