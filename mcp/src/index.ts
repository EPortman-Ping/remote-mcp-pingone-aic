import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { TodoMcpServer } from './mcp'; 
import { authenticationMiddleware } from './auth'; 
import { type Env, MCP_SERVER_SCOPES } from './config';

/**
 * Durable Object Export - Session State Management
 *
 * This export identifies the TodoMCPServer (an McpAgent base class) as the stateful backing logic for
 * the durable object binding. The cloudflare runtime uses this to instantiate a unique, isolated instance
 * per MCP session, ensuring state continuity and persistence across the worker's stateless HTTP requests.
 */
export { TodoMcpServer };

/**
 * Worker Export - Metadata & MCP Router (HTTP Interface)
 *
 * Hono router, which serves as the public entry point for all incoming HTTP requests.
 * Manages MCP client discovery and authenticated MCP communication.
 *   - Metadata Server: Serves well-known documents to guide MCP clients through the registration/authorization process
 *   - Authentication Gate: Validates the MCP client's subject token (user token) before routing.
 *   - Stateful Router: Connects the authenticated request to the correct TodoMcpServer durable object instance.
 */
export default new Hono<{ Bindings: Env }>()
  .use(cors())

  // Protected Resource Metadata - MCP Spec
  // Advertises this MCP server's protected resource details (URL, scopes, authority) and
  // directs MCP clients to the external authorization server (PingOne AIC).
  // Uses our own server as the authorization server URL to proxy requests and avoid CORS issues.
  .get('/.well-known/oauth-protected-resource', (c) => {
    const origin = new URL(c.req.url).origin;
    return c.json({
      resource: c.env.MCP_SERVER_IDENTIFIER.replace(/\/$/, ''),
      authorization_servers: [origin],
      scopes_supported: MCP_SERVER_SCOPES,
    });
  })

  // Resource-specific metadata endpoint for the /mcp path
  // MCP clients may look for metadata at /.well-known/oauth-protected-resource/{resource}
  .get('/.well-known/oauth-protected-resource/mcp', (c) => {
    const origin = new URL(c.req.url).origin;
    return c.json({
      resource: c.env.MCP_SERVER_IDENTIFIER.replace(/\/$/, ''),
      authorization_servers: [origin],
      scopes_supported: MCP_SERVER_SCOPES,
    });
  })

  // Authorization Server Metadata - RFC 8414
  // Advertises this MCP server's necessary endpoints for MCP clients to perform DCR
  // and initiate the correct authorization code flow (OIDC login).
  // Proxies the PingOne AIC metadata and rewrites URLs to use our server as a proxy to avoid CORS issues.
  .get('/.well-known/oauth-authorization-server', async (c) => {
    const response = await fetch(`${c.env.PING_AIC_ISSUER}/.well-known/openid-configuration`);
    const pingAicConfig = await response.json() as any;
    const origin = new URL(c.req.url).origin;
    return c.json({
      issuer: c.env.PING_AIC_ISSUER,
      jwks_uri: pingAicConfig.jwks_uri,
      scopes_supported: pingAicConfig.scopes_supported,
      registration_endpoint: `${origin}/oauth/register`,
      authorization_endpoint: pingAicConfig.authorization_endpoint,
      token_endpoint: `${origin}/oauth/token`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
    });
  })

  // Registration endpoint proxy - forwards DCR requests to PingOne AIC
  // This avoids CORS issues when the browser-based MCP Inspector registers a new client
  .post('/oauth/register', async (c) => {
    const response = await fetch(`${c.env.PING_AIC_ISSUER}/.well-known/openid-configuration`);
    const pingAicConfig = await response.json() as any;
    const body = await c.req.text();

    console.log('DCR Request body:', body);
    console.log('Forwarding to:', pingAicConfig.registration_endpoint);

    const registrationResponse = await fetch(pingAicConfig.registration_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body,
    });

    const data = await registrationResponse.json();
    console.log('DCR Response status:', registrationResponse.status);
    console.log('DCR Response data:', JSON.stringify(data, null, 2));

    if (!registrationResponse.ok) {
      console.error('DCR failed:', data);
    }

    return c.json(data, registrationResponse.status);
  })

  // Token endpoint proxy - forwards token requests to PingOne AIC
  // This avoids CORS issues when the browser-based MCP Inspector exchanges the authorization code for tokens
  .post('/oauth/token', async (c) => {
    const body = await c.req.text();
    const response = await fetch(`${c.env.PING_AIC_ISSUER}/access_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    });
    const data = await response.json();
    return c.json(data, response.status);
  })

  // Applies the auth middleware to validate the MCP client's subject token (the user token),
  // and then injects the claims/token into the stateful durable object execution context.
  .use('/mcp', authenticationMiddleware)

  // Routes the authenticated request to the correct durable object (`TodoMcpServer`).
  // This enables persistent MCP communication via Streamable HTTP Transport
  .route('/mcp', new Hono().mount('/', TodoMcpServer.serve('/mcp').fetch));
