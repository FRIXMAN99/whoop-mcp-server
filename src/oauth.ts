import crypto from 'node:crypto';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';

const REDIRECT = process.env.WHOOP_REDIRECT_URI ?? 'http://localhost:3000/callback';
const BASE = REDIRECT.replace(/\/callback\/?$/, '');

const SIGN_KEY = crypto
	.createHash('sha256')
	.update('mcp-oauth-shim:' + (process.env.WHOOP_CLIENT_SECRET ?? 'fallback'))
	.digest();

function b64url(buf: Buffer): string {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sign(payload: Record<string, unknown>): string {
	const body = b64url(Buffer.from(JSON.stringify(payload)));
	const sig = b64url(crypto.createHmac('sha256', SIGN_KEY).update(body).digest());
	return body + '.' + sig;
}

function verify(token: string): Record<string, unknown> | null {
	const parts = token.split('.');
	if (parts.length !== 2) return null;
	const expected = b64url(crypto.createHmac('sha256', SIGN_KEY).update(parts[0]).digest());
	const a = Buffer.from(parts[1]);
	const b = Buffer.from(expected);
	if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
	try {
		const payload = JSON.parse(Buffer.from(parts[0], 'base64').toString()) as Record<string, unknown>;
		if (typeof payload.exp === 'number' && Date.now() > payload.exp) return null;
		return payload;
	} catch {
		return null;
	}
}

function pkceOk(verifier: string, challenge: string): boolean {
	return b64url(crypto.createHash('sha256').update(verifier).digest()) === challenge;
}

export function installOAuth(app: Express): void {
	app.use(express.urlencoded({ extended: true }));

	const meta = {
		issuer: BASE,
		authorization_endpoint: BASE + '/authorize',
		token_endpoint: BASE + '/token',
		registration_endpoint: BASE + '/register',
		response_types_supported: ['code'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		code_challenge_methods_supported: ['S256'],
		token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
		scopes_supported: ['whoop'],
	};

	app.get(/^\/\.well-known\/oauth-authorization-server.*/, (_req: Request, res: Response) => {
		res.setHeader('Access-Control-Allow-Origin', '*');
		res.json(meta);
	});

	app.get(/^\/\.well-known\/oauth-protected-resource.*/, (_req: Request, res: Response) => {
		res.setHeader('Access-Control-Allow-Origin', '*');
		res.json({ resource: BASE + '/mcp', authorization_servers: [BASE] });
	});

	app.post('/register', (req: Request, res: Response) => {
		res.setHeader('Access-Control-Allow-Origin', '*');
		const body = (req.body ?? {}) as Record<string, unknown>;
		res.status(201).json({
			client_id: 'mcp-' + b64url(crypto.randomBytes(12)),
			client_id_issued_at: Math.floor(Date.now() / 1000),
			redirect_uris: body.redirect_uris ?? [],
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
		});
	});

	app.get('/authorize', (req: Request, res: Response) => {
		const redirectUri = String(req.query.redirect_uri ?? '');
		if (!redirectUri) {
			res.status(400).send('Missing redirect_uri');
			return;
		}
		const state = req.query.state ? String(req.query.state) : '';
		const challenge = String(req.query.code_challenge ?? '');
		const code = sign({ typ: 'code', cc: challenge, exp: Date.now() + 600000 });
		const sep = redirectUri.includes('?') ? '&' : '?';
		res.redirect(302, redirectUri + sep + 'code=' + encodeURIComponent(code) + (state ? '&state=' + encodeURIComponent(state) : ''));
	});

	app.post('/token', (req: Request, res: Response) => {
		res.setHeader('Access-Control-Allow-Origin', '*');
		const body = (req.body ?? {}) as Record<string, string>;
		if (body.grant_type === 'authorization_code') {
			const payload = verify(String(body.code ?? ''));
			if (!payload || payload.typ !== 'code') {
				res.status(400).json({ error: 'invalid_grant' });
				return;
			}
			if (payload.cc && !(body.code_verifier && pkceOk(body.code_verifier, String(payload.cc)))) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'pkce' });
				return;
			}
		} else if (body.grant_type === 'refresh_token') {
			const payload = verify(String(body.refresh_token ?? ''));
			if (!payload || payload.typ !== 'rt') {
				res.status(400).json({ error: 'invalid_grant' });
				return;
			}
		} else {
			res.status(400).json({ error: 'unsupported_grant_type' });
			return;
		}
		const year = 31536000000;
		res.json({
			access_token: sign({ typ: 'at', exp: Date.now() + year }),
			token_type: 'Bearer',
			expires_in: 31536000,
			refresh_token: sign({ typ: 'rt', exp: Date.now() + year }),
			scope: 'whoop',
		});
	});

	app.use('/mcp', (req: Request, res: Response, next: NextFunction) => {
		const auth = req.headers.authorization ?? '';
		const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
		const payload = token ? verify(token) : null;
		if (payload && payload.typ === 'at') {
			next();
			return;
		}
		res.status(401);
		res.setHeader('WWW-Authenticate', 'Bearer resource_metadata="' + BASE + '/.well-known/oauth-protected-resource"');
		res.json({ error: 'unauthorized' });
	});
}
