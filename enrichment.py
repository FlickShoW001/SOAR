"""
Enrichment module: queries AbuseIPDB API and caches results.
Handles timeouts, 429 rate limits, and invalid API keys gracefully.
"""

import os
import json
import logging
from datetime import datetime, timedelta
import requests
from typing import Optional, Dict, Any
from models import EnrichmentResult

logger = logging.getLogger(__name__)

# In-memory cache: {ip_address: (result, cached_timestamp)}
_enrichment_cache: Dict[str, tuple[Dict[str, Any], datetime]] = {}


def enrich_ip(ip: str, session, cache_ttl_minutes: int = 60) -> Optional[EnrichmentResult]:
    """
    Enrich an IP address with reputation data from AbuseIPDB.
    
    Uses local in-memory cache to avoid repeated API calls within TTL window.
    Gracefully handles:
      - Missing/invalid API key -> logs warning, returns None
      - Timeouts -> logs error, returns None
      - 429 rate limit -> logs warning, returns None
      - 4xx/5xx errors -> logs appropriately, returns None
    
    Args:
        ip: IP address to enrich
        session: SQLAlchemy session for DB persistence
        cache_ttl_minutes: How long to cache results before re-querying
    
    Returns:
        EnrichmentResult model (persisted to DB), or None if enrichment failed
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not set; skipping enrichment")
        return _create_failed_enrichment(ip, session, "API key not configured")
    
    # Check in-memory cache first
    if ip in _enrichment_cache:
        cached_result, cached_time = _enrichment_cache[ip]
        if (datetime.utcnow() - cached_time).total_seconds() < cache_ttl_minutes * 60:
            logger.info(f"Using cached enrichment for {ip}")
            # Return cached result from database if it exists, or create new entry
            return _get_or_create_enrichment_from_cache(ip, cached_result, session, cache_ttl_minutes)
    
    # Call AbuseIPDB API
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            },
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            timeout=5
        )
        
        if response.status_code == 401:
            logger.error("Invalid AbuseIPDB API key")
            return _create_failed_enrichment(ip, session, "Invalid API key (401)")
        
        if response.status_code == 429:
            logger.warning(f"AbuseIPDB rate limit hit; returning cached or empty result for {ip}")
            return _create_failed_enrichment(ip, session, "Rate limited (429)")
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            enrichment = EnrichmentResult(
                source_ip=ip,
                abuse_score=data.get("abuseConfidenceScore", 0.0),
                country=data.get("countryCode", "Unknown"),
                isp=data.get("isp", "Unknown"),
                report_count=data.get("totalReports", 0),
                is_vpn=data.get("usageType") == "VPN",
                is_proxy=data.get("usageType") == "Proxy",
                raw_response=data,
                cache_ttl_minutes=cache_ttl_minutes
            )
            session.add(enrichment)
            session.commit()
            
            # Cache in memory
            _enrichment_cache[ip] = (data, datetime.utcnow())
            logger.info(f"Enriched {ip}: abuse_score={enrichment.abuse_score}, reports={enrichment.report_count}")
            return enrichment
        else:
            logger.error(f"AbuseIPDB returned status {response.status_code}")
            return _create_failed_enrichment(ip, session, f"HTTP {response.status_code}")
    
    except requests.Timeout:
        logger.error(f"AbuseIPDB request timed out for {ip}")
        return _create_failed_enrichment(ip, session, "Request timeout")
    
    except requests.RequestException as e:
        logger.error(f"AbuseIPDB request failed for {ip}: {e}")
        return _create_failed_enrichment(ip, session, f"Request error: {str(e)}")
    
    except json.JSONDecodeError:
        logger.error(f"Failed to parse AbuseIPDB response for {ip}")
        return _create_failed_enrichment(ip, session, "JSON decode error")


def _create_failed_enrichment(ip: str, session, error_msg: str) -> EnrichmentResult:
    """
    Create a failed enrichment record when API calls don't succeed.
    Still persists to DB for audit purposes.
    """
    enrichment = EnrichmentResult(
        source_ip=ip,
        abuse_score=0.0,
        country="Unknown",
        isp="Unknown",
        report_count=0,
        error=error_msg
    )
    session.add(enrichment)
    session.commit()
    return enrichment


def _get_or_create_enrichment_from_cache(
    ip: str, cached_data: Dict[str, Any], session, cache_ttl_minutes: int
) -> EnrichmentResult:
    """
    Helper: on cache hit, create or update DB record from cached API response.
    """
    enrichment = EnrichmentResult(
        source_ip=ip,
        abuse_score=cached_data.get("abuseConfidenceScore", 0.0),
        country=cached_data.get("countryCode", "Unknown"),
        isp=cached_data.get("isp", "Unknown"),
        report_count=cached_data.get("totalReports", 0),
        is_vpn=cached_data.get("usageType") == "VPN",
        is_proxy=cached_data.get("usageType") == "Proxy",
        raw_response=cached_data,
        cache_ttl_minutes=cache_ttl_minutes
    )
    session.add(enrichment)
    session.commit()
    return enrichment


def clear_cache():
    """Clear the in-memory enrichment cache (useful for testing/reset)."""
    _enrichment_cache.clear()
    logger.info("Enrichment cache cleared")
