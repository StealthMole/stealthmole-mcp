# StealthMole MCP Server

MCP (Model Context Protocol) server for accessing StealthMole threat intelligence API. Search and monitor threats across Deep & Dark Web through Claude and other MCP clients.

## Features

### 🔍 Comprehensive API Coverage

- **Darkweb Tracker (DT)**: Search Deep & Dark web content across 50+ indicators
- **Telegram Tracker (TT)**: Search Telegram channels, users, and messages
- **Credential Lookout (CL)**: Search leaked credentials from breaches
- **Compromised Data Set (CDS)**: Search infected device leaks from stealer malware
- **Combo Binder (CB)**: Search ID/Password combo leaks
- **ULP Binder (UB)**: Search URL-Login-Password format leaks
- **Ransomware Monitoring (RM)**: Monitor ransomware group breach incidents
- **Government Monitoring (GM)**: Monitor threats against government sector
- **Leaked Monitoring (LM)**: Monitor threats against enterprise sector
- **Management API**: Track API usage quotas

### 🔐 Authentication

- JWT-based authentication with HS256 signing
- Automatic token generation and management
- Secure session-level credential storage

## Prerequisites

- **Python**: 3.10 or higher
- **StealthMole API Credentials**: Get your access_key and secret_key from [StealthMole](https://stealthmole.com)
- **Smithery API key** (optional): For deployment at [smithery.ai/account/api-keys](https://smithery.ai/account/api-keys)

## Installation

### Development Setup

```bash
# Install dependencies
uv sync

# Run the server
uv run dev

# Test interactively
uv run playground
```

### Using with Claude Desktop

Add to your Claude Desktop configuration file:

**MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "stealthmole": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/stealthmole-mcp",
        "run",
        "start"
      ],
      "env": {
        "STEALTHMOLE_ACCESS_KEY": "your_access_key",
        "STEALTHMOLE_SECRET_KEY": "your_secret_key"
      }
    }
  }
}
```

Replace `/absolute/path/to/stealthmole-mcp` with the actual path to this directory.

## Available Tools

### Darkweb Tracker

#### `dt_search_targets`
Get list of searchable targets for an indicator
```
indicator: keyword, email, domain, ip, bitcoin, etc.
Returns: Available targets for the indicator
```

#### `dt_search_target`
Search for specific indicator and targets
```
indicator: Search type
targets: Comma-separated target list
text: Search query (supports AND, OR, NOT)
limit: Results limit (max: 100)
order_type: createDate or value
order: asc or desc
```

#### `dt_search_all`
Search across all targets for an indicator
```
indicator: Search type
text: Search query
limit: Results limit (max: 100)
```

#### `dt_search_by_id`
Get paginated results using search ID
```
search_id: ID from previous search
cursor: Pagination cursor
limit: Results limit (max: 100)
```

#### `dt_get_node_details`
Get detailed information for a node
```
node_id: Node ID from search results
parent_id: Optional parent node ID
data_from: Include data source list
include_url: Include URL list
include_contents: Include HTML source
```

### Telegram Tracker

#### `tt_search_targets`
Get searchable targets for Telegram indicator
```
indicator: keyword, telegram.channel, telegram.user, etc.
```

#### `tt_search_target`
Search Telegram for specific targets
```
indicator: Search type
targets: Comma-separated target list
text: Search query
limit: Results limit (max: 100)
```

#### `tt_get_node_details`
Get detailed Telegram node information
```
node_id: Node ID from search results
```

### Credential Lookout

#### `cl_search`
Search for leaked credentials
```
query: Search with indicators (domain:, email:, id:, password:, after:, before:)
limit: Results limit (max: 50)
cursor: Pagination cursor
start/end: UTC timestamp filters
```

Example queries:
- `domain:example.com` - All leaks for domain
- `email:user@example.com` - Specific email leaks
- `domain:example.com AND after:2024-01` - Recent leaks

### Compromised Data Set

#### `cds_search`
Search infected device leaks
```
query: Search with indicators (domain:, url:, email:, id:, password:, ip:, country:, after:, before:)
limit: Results limit (max: 50)
```

#### `cds_get_node_details`
Get detailed CDS information (requires Cyber Security Edition)
```
node_id: Node ID from search results
Returns: Stealer path, type, and full device info
```

### Combo Binder

#### `cb_search`
Search ID/Password combo leaks
```
query: Search with indicators (domain:, email:, id:, password:, after:, before:)
limit: Results limit (max: 50)
```

### ULP Binder

#### `ub_search`
Search URL-Login-Password format leaks
```
query: Search with indicators (domain:, url:, email:, id:, password:, after:, before:)
limit: Results limit (max: 50)
```

### Monitoring APIs

#### `rm_search` - Ransomware Monitoring
Monitor ransomware group breach incidents
```
query: Optional (torurl:, domain:) or empty for recent
limit: Results limit (max: 50)
order_type: detectionTime, victim, or attackGroup
```

#### `gm_search` - Government Monitoring
Monitor threats against government sector
```
query: Optional (url:, id:) or empty for recent
limit: Results limit (max: 50)
order_type: detectionTime, title, or author
```

#### `lm_search` - Leaked Monitoring
Monitor threats against enterprise sector
```
query: Optional (url:, id:) or empty for recent
limit: Results limit (max: 50)
```

### Management

#### `get_user_quotas`
Get API usage quotas for current month
```
Returns: Allowed and used queries per service
```

## Search Query Syntax

### Indicators

Darkweb Tracker supports 50+ indicators:

**Network**: domain, ip, tor, torurl, i2p, i2purl, url
**Identity**: email, id, tel, kssn
**Financial**: bitcoin, ethereum, monero, creditcard
**Files**: document, exefile, image, hash, blueprint
**Social**: facebook, twitter, instagram, telegram, discord
**Security**: cve, ioc, malware

### Operators

- **AND**: Both terms must be present
- **OR**: Either term must be present (max 3 per query)
- **NOT**: Exclude term from results
- **Max total**: 5 operators per query

### Examples

```
keyword search:
  "ransomware"

Indicator search:
  email:user@example.com
  domain:target.com
  bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

Combined operators:
  domain:example.com AND email:admin
  ip:192.168.1.1 OR ip:10.0.0.1
  domain:target.com AND NOT test

Time filters:
  domain:example.com AND after:2024-01
  email:admin AND before:2024-06-01
```

## Resources

The server provides built-in documentation resources:

- `stealthmole://api-info` - API overview and service information
- `stealthmole://indicators` - Complete list of Darkweb Tracker indicators

## Error Handling

Common API error codes:

- `401` - Invalid or expired token
- `400` - Invalid parameters (limit, cursor, etc.)
- `404` - Resource not found
- `422` - Bulk export required (>1M results)
- `426` - Query limit exceeded

## API Limits

- **Darkweb Tracker**: Max 100 results per request
- **Other APIs**: Max 50 results per request
- **Operators**: Max 3 OR, max 5 total per query
- **Bulk Export**: Contact support for >1M results

## Development

### Project Structure

```
stealthmole-mcp/
├── src/stealthmole_mcp/
│   ├── __init__.py
│   └── server.py          # Main server implementation
├── pyproject.toml         # Project configuration
└── README.md             # This file
```

### Running Tests

```bash
# Interactive testing
uv run playground

# Try example queries:
dt_search_targets(indicator="keyword")
cl_search(query="domain:example.com")
get_user_quotas()
```

## Deployment

### Deploy to Smithery

1. Push code to GitHub
2. Deploy at [smithery.ai/new](https://smithery.ai/new)
3. Configure with your StealthMole credentials

### Self-Hosting

Run the server directly:

```bash
# Production mode
uv run start

# Development mode with auto-reload
uv run dev
```

## Security Notes

⚠️ **Important**: Keep your API credentials secure

- Never commit credentials to version control
- Use environment variables or secure configuration
- Rotate keys regularly
- Monitor API usage for anomalies

## Support

- **StealthMole API Documentation**: [api.stealthmole.com](https://api.stealthmole.com)
- **MCP Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
- **Smithery Platform**: [smithery.ai](https://smithery.ai)

## License

This MCP server implementation is provided as-is. StealthMole API access requires valid subscription and credentials.

## Version

Current version: 0.1.0 (November 2024)
Based on StealthMole API v2.2
