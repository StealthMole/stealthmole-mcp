"""StealthMole MCP Server

A FastMCP server providing access to StealthMole's threat intelligence and
dark web monitoring APIs including Darkweb Tracker, Telegram Tracker,
Credential Lookout, and more.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import jwt
from fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP(
    name="StealthMole",
    instructions="""
    StealthMole MCP server provides access to comprehensive threat intelligence
    and dark web monitoring capabilities:

    - Darkweb Tracker: Search and monitor dark web, deep web, and surface web content
    - Telegram Tracker: Monitor Telegram channels, groups, messages, and users
    - Credential Lookout: Search for leaked credentials and account information
    - Compromised Data Set: Find infected device data and stealer malware leaks
    - Combo Binder: Search for leaked ID/Password combos
    - ULP Binder: Search for URL-Login-Password combinations
    - Ransomware Monitoring: Track ransomware group activities and victims
    - Government/Leaked Monitoring: Monitor threats against public and private sectors

    Authentication can be provided in two ways:
    1. Environment variables (STEALTHMOLE_ACCESS_KEY, STEALTHMOLE_SECRET_KEY) - used by default
    2. Function arguments (access_key, secret_key) - override environment variables when provided

    All tools accept optional access_key and secret_key parameters for flexible authentication.
    """
)

# API Configuration
API_BASE_URL = "https://api.stealthmole.com"
DEFAULT_ACCESS_KEY = os.getenv("STEALTHMOLE_ACCESS_KEY")
DEFAULT_SECRET_KEY = os.getenv("STEALTHMOLE_SECRET_KEY")


def generate_jwt_token(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> str:
    """Generate JWT authentication token for StealthMole API.

    Args:
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        JWT token string ready to use in Authorization header

    Raises:
        ValueError: If credentials are not provided and not in environment
    """
    key = access_key or DEFAULT_ACCESS_KEY
    secret = secret_key or DEFAULT_SECRET_KEY

    if not key or not secret:
        raise ValueError(
            "STEALTHMOLE_ACCESS_KEY and STEALTHMOLE_SECRET_KEY must be provided "
            "either as arguments or environment variables"
        )

    payload = {
        "access_key": key,
        "nonce": str(uuid.uuid4()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return f"Bearer {token}"


async def make_api_request(
    endpoint: str,
    params: Optional[Dict[str, Any]] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Make authenticated request to StealthMole API.

    Args:
        endpoint: API endpoint path (e.g., "/v2/dt/search/keyword/targets")
        params: Optional query parameters
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        JSON response from API

    Raises:
        httpx.HTTPError: If request fails
        ValueError: If credentials are not provided
    """
    headers = {
        "Authorization": generate_jwt_token(access_key, secret_key),
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{API_BASE_URL}{endpoint}",
            headers=headers,
            params=params or {},
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()


# ============================================================================
# DARKWEB TRACKER API
# ============================================================================

@mcp.tool()
async def dt_search_targets(
    indicator: str,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get list of searchable targets for a Darkweb Tracker indicator.

    Args:
        indicator: Search indicator type (e.g., keyword, domain, email, ip, etc.)
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        List of searchable targets and total count
    """
    endpoint = f"/v2/dt/search/{indicator}/targets"
    return await make_api_request(endpoint, access_key=access_key, secret_key=secret_key)


@mcp.tool()
async def dt_search(
    indicator: str,
    targets: str,
    text: str,
    limit: int = 100,
    order_type: Optional[str] = None,
    order: str = "desc",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Darkweb Tracker for specific indicator and targets.

    Args:
        indicator: Search indicator type (keyword, domain, email, etc.)
        targets: Comma-separated list of target types to search
        text: Search query text (supports AND, OR, NOT operators)
        limit: Maximum results (default: 100, max: 100)
        order_type: Sort by 'createDate' or 'value'
        order: Sort order 'asc' or 'desc' (default: desc)
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Search results with pagination cursor
    """
    params = {
        "targets": targets,
        "text": text,
        "limit": limit,
        "order": order,
    }
    if order_type:
        params["orderType"] = order_type

    endpoint = f"/v2/dt/search/{indicator}/target"
    return await make_api_request(endpoint, params, access_key, secret_key)


@mcp.tool()
async def dt_search_all(
    indicator: str,
    text: str,
    limit: int = 100,
    order_type: Optional[str] = None,
    order: str = "desc",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search all Darkweb Tracker targets for an indicator.

    Args:
        indicator: Search indicator type
        text: Search query text
        limit: Maximum results (default: 100, max: 100)
        order_type: Sort by 'createDate' or 'value'
        order: Sort order 'asc' or 'desc'
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Search results across all targets
    """
    params = {
        "text": text,
        "limit": limit,
        "order": order,
    }
    if order_type:
        params["orderType"] = order_type

    endpoint = f"/v2/dt/search/{indicator}/target/all"
    return await make_api_request(endpoint, params, access_key, secret_key)


@mcp.tool()
async def dt_search_by_id(
    search_id: str,
    limit: int = 100,
    cursor: int = 0,
    order_type: Optional[str] = None,
    order: str = "desc",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get paginated results from a Darkweb Tracker search by ID.

    Args:
        search_id: Search result ID from previous search
        limit: Maximum results (default: 100, max: 100)
        cursor: Pagination cursor (default: 0)
        order_type: Sort by 'createDate' or 'value'
        order: Sort order 'asc' or 'desc'
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Paginated search results
    """
    params = {
        "limit": limit,
        "cursor": cursor,
        "order": order,
    }
    if order_type:
        params["orderType"] = order_type

    endpoint = f"/v2/dt/search/{search_id}"
    return await make_api_request(endpoint, params, access_key, secret_key)


@mcp.tool()
async def dt_get_node(
    node_id: str,
    parent_id: Optional[str] = None,
    data_from: bool = False,
    include_url: bool = False,
    include_contents: bool = True,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information for a Darkweb Tracker node.

    Args:
        node_id: Node ID from search results
        parent_id: Parent node ID (optional)
        data_from: Include data source list
        include_url: Include URL list
        include_contents: Include HTML source contents (default: True)
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Detailed node information
    """
    params = {
        "id": node_id,
        "data_from": data_from,
        "include_url": include_url,
        "include_contents": include_contents,
    }
    if parent_id:
        params["pid"] = parent_id

    endpoint = "/v2/dt/node"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# TELEGRAM TRACKER API
# ============================================================================

@mcp.tool()
async def tt_search_targets(
    indicator: str,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get list of searchable targets for a Telegram Tracker indicator.

    Args:
        indicator: Search indicator type
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        List of searchable targets and total count
    """
    endpoint = f"/v2/tt/search/{indicator}/targets"
    return await make_api_request(endpoint, access_key=access_key, secret_key=secret_key)


@mcp.tool()
async def tt_search(
    indicator: str,
    targets: str,
    text: str,
    limit: int = 100,
    order_type: Optional[str] = None,
    order: str = "desc",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Telegram Tracker for specific indicator and targets.

    Args:
        indicator: Search indicator type
        targets: Comma-separated list of target types
        text: Search query text
        limit: Maximum results (default: 100, max: 100)
        order_type: Sort by 'createDate' or 'value'
        order: Sort order 'asc' or 'desc'
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Search results with pagination
    """
    params = {
        "targets": targets,
        "text": text,
        "limit": limit,
        "order": order,
    }
    if order_type:
        params["orderType"] = order_type

    endpoint = f"/v2/tt/search/{indicator}/target"
    return await make_api_request(endpoint, params, access_key, secret_key)


@mcp.tool()
async def tt_get_node(
    node_id: str,
    parent_id: Optional[str] = None,
    data_from: bool = False,
    include_url: bool = False,
    include_contents: bool = True,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information for a Telegram Tracker node.

    Args:
        node_id: Node ID from search results
        parent_id: Parent node ID (optional)
        data_from: Include data source list
        include_url: Include URL list
        include_contents: Include HTML source contents
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Detailed node information
    """
    params = {
        "id": node_id,
        "data_from": data_from,
        "include_url": include_url,
        "include_contents": include_contents,
    }
    if parent_id:
        params["pid"] = parent_id

    endpoint = "/v2/tt/node"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# CREDENTIAL LOOKOUT API
# ============================================================================

@mcp.tool()
async def cl_search(
    query: str,
    limit: int = 50,
    cursor: int = 0,
    order_type: str = "leakedDate",
    order: str = "desc",
    start: Optional[int] = None,
    end: Optional[int] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Credential Lookout for leaked credentials.

    Args:
        query: Search query (supports domain:, email:, id:, password:, after:, before: indicators)
        limit: Maximum results (default: 50, max: 50)
        cursor: Pagination cursor (default: 0)
        order_type: Sort by leakedDate, domain, email, password, or leakedFrom
        order: Sort order 'asc' or 'desc'
        start: Filter by system add time (UTC timestamp)
        end: Filter by system add time (UTC timestamp)
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Leaked credential search results
    """
    params = {
        "query": query,
        "limit": limit,
        "cursor": cursor,
        "orderType": order_type,
        "order": order,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end

    endpoint = "/v2/cl/search"
    return await make_api_request(endpoint, params, access_key, secret_key)


@mcp.tool()
async def cl_export(
    query: str,
    limit: int = 0,
    order_type: str = "leakedDate",
    order: str = "desc",
    export_type: str = "csv",
    start: Optional[int] = None,
    end: Optional[int] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> str:
    """Export Credential Lookout data as CSV or JSON.

    Args:
        query: Search query
        limit: Maximum results (0 for all data, default: 0)
        order_type: Sort by leakedDate, domain, email, password, or leakedFrom
        order: Sort order 'asc' or 'desc'
        export_type: Export format 'csv' or 'json' (default: csv)
        start: Filter by system add time
        end: Filter by system add time
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        File download URL or exported data
    """
    params = {
        "query": query,
        "limit": limit,
        "orderType": order_type,
        "order": order,
        "exportType": export_type,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end

    endpoint = "/v2/cl/export"
    # Note: This endpoint returns a file, might need special handling
    result = await make_api_request(endpoint, params, access_key, secret_key)
    return str(result)


# ============================================================================
# COMPROMISED DATA SET API
# ============================================================================

@mcp.tool()
async def cds_search(
    query: str,
    limit: int = 50,
    cursor: int = 0,
    order_type: str = "leakedDate",
    order: str = "desc",
    start: Optional[int] = None,
    end: Optional[int] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Compromised Data Set for infected device data.

    Args:
        query: Search query (supports domain:, url:, email:, id:, password:, ip:, country:, after:, before:)
        limit: Maximum results (default: 50, max: 50)
        cursor: Pagination cursor
        order_type: Sort by leakedDate, host, user, password, or regdate
        order: Sort order 'asc' or 'desc'
        start: Filter by system add time
        end: Filter by system add time
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Compromised data search results
    """
    params = {
        "query": query,
        "limit": limit,
        "cursor": cursor,
        "orderType": order_type,
        "order": order,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end

    endpoint = "/v2/cds/search"
    return await make_api_request(endpoint, params, access_key, secret_key)


@mcp.tool()
async def cds_get_node(
    node_id: str,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get detailed information for a Compromised Data Set node.

    Requires Cyber Security Edition.

    Args:
        node_id: Node ID from search results
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Detailed node information including stealer malware details
    """
    params = {"id": node_id}
    endpoint = "/v2/cds/node"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# COMBO BINDER API
# ============================================================================

@mcp.tool()
async def cb_search(
    query: str,
    limit: int = 50,
    cursor: int = 0,
    order_type: str = "leakedDate",
    order: str = "desc",
    start: Optional[int] = None,
    end: Optional[int] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Combo Binder for ID/Password combinations.

    Args:
        query: Search query (supports domain:, email:, id:, password:, after:, before:)
        limit: Maximum results (default: 50, max: 50)
        cursor: Pagination cursor
        order_type: Sort by leakedDate, user, or password
        order: Sort order 'asc' or 'desc'
        start: Filter by system add time
        end: Filter by system add time
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Combo search results
    """
    params = {
        "query": query,
        "limit": limit,
        "cursor": cursor,
        "orderType": order_type,
        "order": order,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end

    endpoint = "/v2/cb/search"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# ULP BINDER API
# ============================================================================

@mcp.tool()
async def ub_search(
    query: str,
    limit: int = 50,
    cursor: int = 0,
    order_type: str = "leakedDate",
    order: str = "desc",
    start: Optional[int] = None,
    end: Optional[int] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search ULP Binder for URL-Login-Password combinations.

    Args:
        query: Search query (supports domain:, url:, email:, id:, password:, after:, before:)
        limit: Maximum results (default: 50, max: 50)
        cursor: Pagination cursor
        order_type: Sort by leakedDate, host, user, or password
        order: Sort order 'asc' or 'desc'
        start: Filter by system add time
        end: Filter by system add time
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        ULP search results
    """
    params = {
        "query": query,
        "limit": limit,
        "cursor": cursor,
        "orderType": order_type,
        "order": order,
    }
    if start:
        params["start"] = start
    if end:
        params["end"] = end

    endpoint = "/v2/ub/search"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# RANSOMWARE MONITORING API
# ============================================================================

@mcp.tool()
async def rm_search(
    query: Optional[str] = None,
    limit: int = 50,
    cursor: int = 0,
    order_type: str = "detectionTime",
    order: str = "desc",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Ransomware Monitoring for ransomware group activities.

    Args:
        query: Search query (supports torurl: for ransomware site, domain: for victim website)
        limit: Maximum results (default: 50, max: 50)
        cursor: Pagination cursor
        order_type: Sort by detectionTime, victim, or attackGroup
        order: Sort order 'asc' or 'desc'
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Ransomware monitoring results
    """
    params = {
        "limit": limit,
        "cursor": cursor,
        "orderType": order_type,
        "order": order,
    }
    if query:
        params["query"] = query

    endpoint = "/v2/rm/search"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# GOVERNMENT MONITORING API
# ============================================================================

@mcp.tool()
async def gm_search(
    query: Optional[str] = None,
    limit: int = 50,
    cursor: int = 0,
    order_type: str = "detectionTime",
    order: str = "desc",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Government Monitoring for threats against public sector.

    Args:
        query: Search query (supports url:, id: for actor)
        limit: Maximum results (default: 50, max: 50)
        cursor: Pagination cursor
        order_type: Sort by detectionTime, title, or author
        order: Sort order 'asc' or 'desc'
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Government monitoring results
    """
    params = {
        "limit": limit,
        "cursor": cursor,
        "orderType": order_type,
        "order": order,
    }
    if query:
        params["query"] = query

    endpoint = "/v2/gm/search"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# LEAKED MONITORING API
# ============================================================================

@mcp.tool()
async def lm_search(
    query: Optional[str] = None,
    limit: int = 50,
    cursor: int = 0,
    order_type: str = "detectionTime",
    order: str = "desc",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Search Leaked Monitoring for threats against private sector.

    Args:
        query: Search query (supports url:, id: for actor)
        limit: Maximum results (default: 50, max: 50)
        cursor: Pagination cursor
        order_type: Sort by detectionTime, title, or author
        order: Sort order 'asc' or 'desc'
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Leaked monitoring results
    """
    params = {
        "limit": limit,
        "cursor": cursor,
        "orderType": order_type,
        "order": order,
    }
    if query:
        params["query"] = query

    endpoint = "/v2/lm/search"
    return await make_api_request(endpoint, params, access_key, secret_key)


# ============================================================================
# MANAGEMENT API
# ============================================================================

@mcp.tool()
async def get_quotas(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get API query usage quotas for all services.

    Args:
        access_key: StealthMole access key (uses env var if not provided)
        secret_key: StealthMole secret key (uses env var if not provided)

    Returns:
        Quota information showing allowed and used queries per service
    """
    endpoint = "/v2/user/quotas"
    return await make_api_request(endpoint, access_key=access_key, secret_key=secret_key)


# Run the server
if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000, path="/mcp")
