# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a proxy server that exposes Qwen models through an OpenAI-compatible API. It supports multiple Qwen accounts with automatic rotation, streaming, tool calling, web search, and MCP (Model Context Protocol).

## Commands

```bash
npm start              # Start the proxy server (src/index.js)
npm run auth:add <id>  # Add a new Qwen account
npm run auth:list      # List all configured accounts
npm run auth:remove <id> # Remove an account
npm run auth:counts    # Show request counts per account
npm run usage         # Show token usage report
```

## Architecture

### Core Components

- **src/index.js** - Express server with routes for `/v1/chat/completions`, `/v1/web/search`, `/v1/models`, `/health`, `/status`, and `/mcp`
- **src/qwen/api.js** - `QwenAPI` class handles API calls to DashScope with account rotation logic
- **src/qwen/auth.js** - `QwenAuthManager` handles OAuth authentication and token refresh
- **src/utils/accountHealthManager.js** - Account health with strike system (blocks accounts progressively after failures)
- **src/mcp.js** - MCP server implementation with SSE transport for `web_search` tool

### Account Rotation Flow

`QwenAPI.executeWithAccountRotation()` coordinates multi-account usage:
1. `getCandidatePool()` - Gets available accounts (not blocked/rate-limited)
2. `getPreparedAccounts()` - Sorts by strikes (ascending) then token expiry (descending)
3. `executeOperationWithAccount()` - Acquires lock, executes request, handles auth errors with refresh retry
4. `AccountHealthManager` - Tracks strikes, blocks accounts progressively (1min, 5min, 15min, 30min, 1hr, 12hr)

### Data Storage

Credentials stored in `~/.qwen/`:
- `oauth_creds.json` - Default account (from qwen-code CLI)
- `oauth_creds_<name>.json` - Named accounts for multi-account setup
- `request_counts.json` - Request counts and token usage
- `account_health.json` - Strike counts and block times

### Key Configuration (src/config.js)

- `port`/`host` - Server binding (default 8080/localhost)
- `apiKey` - Optional API key authentication (comma-separated for multiple)
- `defaultAccount` - Preferred account for requests
- `qwenCodeAuthUse` - Set `false` to ignore default `~/.qwen/oauth_creds.json`

### Request Processing

1. Request arrives at Express route
2. API key validation (if configured)
3. Account selection (explicit header/query or rotation)
4. Token validity check, refresh if needed (with account lock)
5. API call to DashScope (`https://dashscope.aliyuncs.com/compatible-mode/v1`)
6. Response transformation to OpenAI format
7. Usage tracking and account health update
