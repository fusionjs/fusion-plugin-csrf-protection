import {Plugin} from 'fusion-core';
import assert from 'assert';
import crypto from 'crypto';
import base64Url from 'base64-url';
import {verifyMethod, verifyExpiry} from './shared';

function generateSecret() {
  const random = crypto.randomBytes(32);
  const escaped = base64Url.escape(random.toString());
  return escaped.slice(0, 32);
}
function generateToken(secret) {
  const timestamp = Math.round(Date.now() / 1000);
  return tokenize(secret, timestamp.toString());
}
function verifyToken(secret, token) {
  if (!secret || !token) return false;
  const [timestamp] = token.split('-');
  return token === tokenize(secret, timestamp);
}
function tokenize(secret, salt) {
  const hmac = crypto
    .createHmac('sha256', secret)
    .update(salt)
    .digest('base64');
  return salt + '-' + base64Url.escape(hmac);
}

function loadOrGenerateSecret(session) {
  let secret = session.get('csrf-secret');
  if (!secret) {
    secret = generateSecret();
    session.set('csrf-secret', secret);
  }
  return secret;
}

export default ({Session, expire = 86400}) => {
  assert(Session, '{Session} is a required dependency of CsrfToken');
  const ignored = new Set();

  function handleTokenPost(ctx, next) {
    const session = Session.of(ctx);
    const secret = loadOrGenerateSecret(session);
    ctx.set('x-csrf-token', generateToken(secret));
    ctx.status = 200;
    ctx.body = '';
    return next();
  }

  function handleSSR(ctx, next) {
    const session = Session.of(ctx);
    loadOrGenerateSecret(session);
    return next();
  }

  async function checkCSRF(ctx, next) {
    const session = Session.of(ctx);

    const token = ctx.headers['x-csrf-token'];
    const secret = session.get('csrf-secret');
    const isMatchingToken = verifyToken(secret, token);
    const isValidToken = verifyExpiry(token, expire);
    if (!isMatchingToken || !isValidToken) {
      await next();
      ctx.status = 403;
      if (__DEV__) {
        // in development, missing CSRF tokens are most likely a developer mistake
        // so we provide an explanation of how to fix it
        ctx.status = 500;
        ctx.body =
          'CSRF Token configuration error: ' +
          'add the option {fetch: CsrfToken.fetch} to ' +
          'the 2nd argument of app.plugin(yourPlugin)';
      } else {
        // in production, provide a relevant error message
        ctx.body = 'Invalid CSRF token';
      }
      if (ctx.headers.accept === 'application/json') {
        ctx.body = JSON.stringify({error: ctx.body});
      }
    }
  }

  return new Plugin({
    Service: class CsrfProtection {
      ignore(path) {
        ignored.add(path);
      }
    },
    async middleware(ctx, next) {
      if (ctx.element) {
        return handleSSR(ctx, next);
      } else if (ctx.path === '/csrf-token' && ctx.method === 'POST') {
        return handleTokenPost(ctx, next);
      } else if (verifyMethod(ctx.method) && !ignored.has(ctx.path)) {
        return checkCSRF(ctx, next);
      } else return next();
    },
  });
};
