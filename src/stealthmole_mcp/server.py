"""
StealthMole MCP Server
Access threat intelligence from Deep & Dark Web through StealthMole API

API Documentation: https://api.stealthmole.com
"""

import uuid
import jwt
import requests
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, Field
from smithery.decorators import smithery


# Configuration Schema
class ConfigSchema(BaseModel):
    """StealthMole API configuration."""
    access_key: str = Field(..., description="Your StealthMole API access key")
    secret_key: str = Field(..., description="Your StealthMole API secret key")


# Helper Functions
def generate_jwt_token(access_key: str, secret_key: str) -> str:
    """
    Generate JWT authentication token for StealthMole API.

    Args:
        access_key: Issued access key
        secret_key: Issued secret key

    Returns:
        JWT token string
    """
    payload = {
        'access_key': access_key,
        'nonce': str(uuid.uuid4()),
        'iat': int(datetime.now(timezone.utc).timestamp())
    }
    return jwt.encode(payload, secret_key, algorithm='HS256')


def make_api_request(
    endpoint: str,
    access_key: str,
    secret_key: str,
    method: str = 'GET',
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Make authenticated request to StealthMole API.

    Args:
        endpoint: API endpoint path (e.g., '/v2/dt/search/keyword/targets')
        access_key: API access key
        secret_key: API secret key
        method: HTTP method (GET, POST, etc.)
        params: Query parameters
        data: Request body data

    Returns:
        API response as dictionary
    """
    base_url = 'https://api.stealthmole.com'
    url = f"{base_url}{endpoint}"

    # Generate JWT token
    token = generate_jwt_token(access_key, secret_key)
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # Make request
    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        json=data,
        timeout=30
    )

    # Handle response
    response.raise_for_status()
    return response.json()


@smithery.server(config_schema=ConfigSchema)
def create_server():
    """Create and configure the StealthMole MCP server."""

    server = FastMCP("StealthMole API")

    # ========== Darkweb Tracker API ==========

    @server.tool()
    def dt_search_targets(indicator: str, ctx: Context) -> str:
        """
        Get list of searchable targets for a Darkweb Tracker indicator.

        Args:
            indicator: Search indicator (e.g., keyword, email, domain, ip, etc.)
                Available indicators: adsense, analyticsid, band, bitcoin, blueprint,
                creditcard, cve, discord, document, domain, email, ethereum, exefile,
                facebook, filehosting, googledrive, gps, hash, hashstring, i2p, i2purl,
                id, image, instagram, ioc, ip, kakaotalk, keyword, kssn, leakedaudio,
                leakedemailfile, leakedvideo, line, linkedin, malware, monero, otherfile,
                pastebin, pgp, serverstatus, session, shorten, sshkey, sslkey, tel,
                telegram, tor, torurl, twitter, url

        Returns:
            JSON string with list of searchable targets and total count
        """
        config = ctx.session_config
        result = make_api_request(
            f'/v2/dt/search/{indicator}/targets',
            config.access_key,
            config.secret_key
        )
        return str(result)

    @server.tool()
    def dt_search_target(
        indicator: str,
        targets: str,
        text: str,
        limit: int = 100,
        order_type: str = "createDate",
        order: str = "desc",
        ctx: Context = None
    ) -> str:
        """
        Search Darkweb Tracker for specific indicator and targets.

        Args:
            indicator: Search indicator type
            targets: Comma-separated list of targets to search
            text: Search query text (supports AND, OR, NOT operators)
            limit: Number of results (default: 100, max: 100)
            order_type: Sort by createDate or value
            order: asc or desc (default: desc)

        Returns:
            JSON string with search results
        """
        config = ctx.session_config
        params = {
            'targets': targets,
            'text': text,
            'limit': limit,
            'orderType': order_type,
            'order': order
        }
        result = make_api_request(
            f'/v2/dt/search/{indicator}/target',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    @server.tool()
    def dt_search_all(
        indicator: str,
        text: str,
        limit: int = 100,
        order_type: str = "createDate",
        order: str = "desc",
        ctx: Context = None
    ) -> str:
        """
        Search Darkweb Tracker across all targets for an indicator.

        Args:
            indicator: Search indicator type
            text: Search query text
            limit: Number of results (default: 100, max: 100)
            order_type: Sort by createDate or value
            order: asc or desc

        Returns:
            JSON string with search results from all targets
        """
        config = ctx.session_config
        params = {
            'text': text,
            'limit': limit,
            'orderType': order_type,
            'order': order
        }
        result = make_api_request(
            f'/v2/dt/search/{indicator}/target/all',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    @server.tool()
    def dt_search_by_id(
        search_id: str,
        limit: int = 100,
        cursor: int = 0,
        order_type: str = "createDate",
        order: str = "desc",
        ctx: Context = None
    ) -> str:
        """
        Get paginated Darkweb Tracker search results by search ID.

        Args:
            search_id: Search result ID from previous search
            limit: Number of results (default: 100, max: 100)
            cursor: Pagination cursor (default: 0)
            order_type: Sort by createDate or value
            order: asc or desc

        Returns:
            JSON string with paginated results
        """
        config = ctx.session_config
        params = {
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        result = make_api_request(
            f'/v2/dt/search/{search_id}',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    @server.tool()
    def dt_get_node_details(
        node_id: str,
        parent_id: Optional[str] = None,
        data_from: bool = False,
        include_url: bool = False,
        include_contents: bool = True,
        ctx: Context = None
    ) -> str:
        """
        Get detailed information for a Darkweb Tracker node.

        Args:
            node_id: Node ID from search results
            parent_id: Parent node ID (optional)
            data_from: Include data source list
            include_url: Include URL list
            include_contents: Include HTML source contents

        Returns:
            JSON string with detailed node information
        """
        config = ctx.session_config
        params = {
            'id': node_id,
            'data_from': data_from,
            'include_url': include_url,
            'include_contents': include_contents
        }
        if parent_id:
            params['pid'] = parent_id

        result = make_api_request(
            '/v2/dt/node',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Telegram Tracker API ==========

    @server.tool()
    def tt_search_targets(indicator: str, ctx: Context) -> str:
        """
        Get list of searchable targets for a Telegram Tracker indicator.

        Args:
            indicator: Search indicator (e.g., keyword, telegram.channel, telegram.user, etc.)

        Returns:
            JSON string with list of searchable targets
        """
        config = ctx.session_config
        result = make_api_request(
            f'/v2/tt/search/{indicator}/targets',
            config.access_key,
            config.secret_key
        )
        return str(result)

    @server.tool()
    def tt_search_target(
        indicator: str,
        targets: str,
        text: str,
        limit: int = 100,
        order_type: str = "createDate",
        order: str = "desc",
        ctx: Context = None
    ) -> str:
        """
        Search Telegram Tracker for specific indicator and targets.

        Args:
            indicator: Search indicator type
            targets: Comma-separated list of targets
            text: Search query text
            limit: Number of results (max: 100)
            order_type: Sort by createDate or value
            order: asc or desc

        Returns:
            JSON string with search results
        """
        config = ctx.session_config
        params = {
            'targets': targets,
            'text': text,
            'limit': limit,
            'orderType': order_type,
            'order': order
        }
        result = make_api_request(
            f'/v2/tt/search/{indicator}/target',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    @server.tool()
    def tt_get_node_details(
        node_id: str,
        parent_id: Optional[str] = None,
        data_from: bool = False,
        include_url: bool = False,
        include_contents: bool = True,
        ctx: Context = None
    ) -> str:
        """
        Get detailed information for a Telegram Tracker node.

        Args:
            node_id: Node ID from search results
            parent_id: Parent node ID (optional)
            data_from: Include data source list
            include_url: Include URL list
            include_contents: Include HTML source contents

        Returns:
            JSON string with detailed node information
        """
        config = ctx.session_config
        params = {
            'id': node_id,
            'data_from': data_from,
            'include_url': include_url,
            'include_contents': include_contents
        }
        if parent_id:
            params['pid'] = parent_id

        result = make_api_request(
            '/v2/tt/node',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Credential Lookout API ==========

    @server.tool()
    def cl_search(
        query: str,
        limit: int = 50,
        cursor: int = 0,
        order_type: str = "LeakedDate",
        order: str = "desc",
        start: Optional[int] = None,
        end: Optional[int] = None,
        ctx: Context = None
    ) -> str:
        """
        Search Credential Lookout for leaked credentials.

        Args:
            query: Search query with indicators (domain:, email:, id:, password:, after:, before:)
            limit: Number of results (default: 50, max: 50)
            cursor: Pagination cursor
            order_type: Sort by LeakedDate, domain, email, password, or leakedFrom
            order: asc or desc
            start: Filter by UTC timestamp (data added after)
            end: Filter by UTC timestamp (data added before)

        Returns:
            JSON string with leaked credential results
        """
        config = ctx.session_config
        params = {
            'query': query,
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        if start:
            params['start'] = start
        if end:
            params['end'] = end

        result = make_api_request(
            '/v2/cl/search',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Compromised Data Set API ==========

    @server.tool()
    def cds_search(
        query: str,
        limit: int = 50,
        cursor: int = 0,
        order_type: str = "LeakedDate",
        order: str = "desc",
        start: Optional[int] = None,
        end: Optional[int] = None,
        ctx: Context = None
    ) -> str:
        """
        Search Compromised Data Set for infected device leaks.

        Args:
            query: Search query with indicators (domain:, url:, email:, id:, password:, ip:, country:, after:, before:)
            limit: Number of results (default: 50, max: 50)
            cursor: Pagination cursor
            order_type: Sort by LeakedDate, host, user, password, or regdate
            order: asc or desc
            start: Filter by UTC timestamp
            end: Filter by UTC timestamp

        Returns:
            JSON string with compromised data results
        """
        config = ctx.session_config
        params = {
            'query': query,
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        if start:
            params['start'] = start
        if end:
            params['end'] = end

        result = make_api_request(
            '/v2/cds/search',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    @server.tool()
    def cds_get_node_details(node_id: str, ctx: Context) -> str:
        """
        Get detailed information for a Compromised Data Set node (Cyber Security Edition required).

        Args:
            node_id: Node ID from search results

        Returns:
            JSON string with detailed CDS information including stealer path and type
        """
        config = ctx.session_config
        params = {'id': node_id}
        result = make_api_request(
            '/v2/cds/node',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Combo Binder API ==========

    @server.tool()
    def cb_search(
        query: str,
        limit: int = 50,
        cursor: int = 0,
        order_type: str = "LeakedDate",
        order: str = "desc",
        start: Optional[int] = None,
        end: Optional[int] = None,
        ctx: Context = None
    ) -> str:
        """
        Search Combo Binder for leaked ID/Password combos.

        Args:
            query: Search query with indicators (domain:, email:, id:, password:, after:, before:)
            limit: Number of results (max: 50)
            cursor: Pagination cursor
            order_type: Sort by LeakedDate, user, or password
            order: asc or desc
            start: Filter by UTC timestamp
            end: Filter by UTC timestamp

        Returns:
            JSON string with combo leak results
        """
        config = ctx.session_config
        params = {
            'query': query,
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        if start:
            params['start'] = start
        if end:
            params['end'] = end

        result = make_api_request(
            '/v2/cb/search',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== ULP Binder API ==========

    @server.tool()
    def ub_search(
        query: str,
        limit: int = 50,
        cursor: int = 0,
        order_type: str = "LeakedDate",
        order: str = "desc",
        start: Optional[int] = None,
        end: Optional[int] = None,
        ctx: Context = None
    ) -> str:
        """
        Search ULP Binder for leaked accounts in URL-Login-Password format.

        Args:
            query: Search query with indicators (domain:, url:, email:, id:, password:, after:, before:)
            limit: Number of results (max: 50)
            cursor: Pagination cursor
            order_type: Sort by LeakedDate, host, user, or password
            order: asc or desc
            start: Filter by UTC timestamp
            end: Filter by UTC timestamp

        Returns:
            JSON string with ULP leak results
        """
        config = ctx.session_config
        params = {
            'query': query,
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        if start:
            params['start'] = start
        if end:
            params['end'] = end

        result = make_api_request(
            '/v2/ub/search',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Ransomware Monitoring API ==========

    @server.tool()
    def rm_search(
        query: Optional[str] = None,
        limit: int = 50,
        cursor: int = 0,
        order_type: str = "detectionTime",
        order: str = "desc",
        ctx: Context = None
    ) -> str:
        """
        Search Ransomware Monitoring for ransomware breach incidents.

        Args:
            query: Search query with indicators (torurl:, domain:) or empty for recent list
            limit: Number of results (max: 50)
            cursor: Pagination cursor
            order_type: Sort by detectionTime, victim, or attackGroup
            order: asc or desc

        Returns:
            JSON string with ransomware incident results
        """
        config = ctx.session_config
        params = {
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        if query:
            params['query'] = query

        result = make_api_request(
            '/v2/rm/search',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Government Monitoring API ==========

    @server.tool()
    def gm_search(
        query: Optional[str] = None,
        limit: int = 50,
        cursor: int = 0,
        order_type: str = "detectionTime",
        order: str = "desc",
        ctx: Context = None
    ) -> str:
        """
        Search Government Monitoring for threats against government and public sector.

        Args:
            query: Search query with indicators (url:, id:) or empty for recent list
            limit: Number of results (max: 50)
            cursor: Pagination cursor
            order_type: Sort by detectionTime, title, or author
            order: asc or desc

        Returns:
            JSON string with government threat results
        """
        config = ctx.session_config
        params = {
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        if query:
            params['query'] = query

        result = make_api_request(
            '/v2/gm/search',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Leaked Monitoring API ==========

    @server.tool()
    def lm_search(
        query: Optional[str] = None,
        limit: int = 50,
        cursor: int = 0,
        order_type: str = "detectionTime",
        order: str = "desc",
        ctx: Context = None
    ) -> str:
        """
        Search Leaked Monitoring for threats against enterprise and private sector.

        Args:
            query: Search query with indicators (url:, id:) or empty for recent list
            limit: Number of results (max: 50)
            cursor: Pagination cursor
            order_type: Sort by detectionTime, title, or author
            order: asc or desc

        Returns:
            JSON string with leaked threat results
        """
        config = ctx.session_config
        params = {
            'limit': limit,
            'cursor': cursor,
            'orderType': order_type,
            'order': order
        }
        if query:
            params['query'] = query

        result = make_api_request(
            '/v2/lm/search',
            config.access_key,
            config.secret_key,
            params=params
        )
        return str(result)

    # ========== Management API ==========

    @server.tool()
    def get_user_quotas(ctx: Context) -> str:
        """
        Get API query usage per service for the current month.

        Returns:
            JSON string with quota information (allowed and used queries) for each service
        """
        config = ctx.session_config
        result = make_api_request(
            '/v2/user/quotas',
            config.access_key,
            config.secret_key
        )
        return str(result)

    # ========== Resources ==========

    @server.resource("stealthmole://api-info")
    def api_info() -> str:
        """StealthMole API information and documentation."""
        return """
StealthMole API v2.2 (November 2024)

Base URL: https://api.stealthmole.com

Available Services:
1. Darkweb Tracker (DT) - Search Deep & Dark web content
2. Telegram Tracker (TT) - Search Telegram channels, users, messages
3. Credential Lookout (CL) - Search leaked credentials
4. Compromised Data Set (CDS) - Search infected device leaks
5. Combo Binder (CB) - Search ID/Password combos
6. ULP Binder (UB) - Search URL-Login-Password leaks
7. Ransomware Monitoring (RM) - Monitor ransomware incidents
8. Government Monitoring (GM) - Monitor government sector threats
9. Leaked Monitoring (LM) - Monitor enterprise threats
10. Management API - Track API usage quotas

Authentication: JWT tokens with HS256 signing
Supported Operators: AND, OR, NOT (max 3 OR, max 5 total per query)

For detailed documentation, visit: https://api.stealthmole.com
        """

    @server.resource("stealthmole://indicators")
    def indicators_info() -> str:
        """Available search indicators for Darkweb Tracker."""
        return """
Darkweb Tracker Indicators:

Network & Infrastructure:
- domain, ip, tor, torurl, i2p, i2purl, url

Identifiers:
- email, id, tel, kssn (Korean SSN)

Financial:
- bitcoin, ethereum, monero, creditcard

Files:
- document, exefile, image, otherfile, leakedaudio, leakedemailfile, leakedvideo
- hash, hashstring, blueprint

Social & Messaging:
- facebook, twitter, instagram, linkedin, telegram, discord, kakaotalk, line, session

Services & Data:
- googledrive, filehosting, pastebin, shorten
- pgp, sshkey, sslkey, serverstatus

Security:
- cve, ioc, malware

Misc:
- adsense, analyticsid, gps, keyword, band
        """

    return server
