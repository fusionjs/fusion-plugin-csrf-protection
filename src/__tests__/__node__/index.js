import App from 'fusion-core';
import {request, render} from 'fusion-test-utils';
import test from 'tape-cup';
import CsrfPlugin from '../../server';
import {GenericSessionToken} from 'fusion-types';
import {request, render} from 'fusion-test-utils';
import App from 'fusion-core';
import {CSRFTokenExpire, CSRFIgnoreRoutes} from '../../shared';

function getSession() {
  const state = {};
  const Session = {
    from() {
      return {
        set(key, value) {
          return (state[key] = value);
        },
        get(key) {
          return state[key];
        },
      };
    },
  };
  return Session;
}

test.only('valid token', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.register(GenericSessionToken, () => Session);
  app.register(CsrfPlugin);
  app.resolve();
  const ctx = await request(app, '/csrf-token', {method: 'POST'});
  t.ok(ctx.response.headers['x-csrf-token'], 'has token');
  t.equal(ctx.response.status, 200, 'has right status');
  t.equal(ctx.response.body, '', 'has empty body');
  const secret = Session.from(ctx).get('csrf-secret');
  t.ok(secret, 'sets a session secret');

  const renderCtx = await render(app, '/');
  t.equal(ctx.response.status, 200, 'has right status');
  t.equal(
    secret,
    Session.from(renderCtx).get('csrf-secret'),
    'does not change the session secret'
  );
  const postCtx = await request(app, '/test', {
    method: 'POST',
    headers: {
      'x-csrf-token': ctx.response.headers['x-csrf-token'],
    },
  });
  t.equal(postCtx.response.status, 200);
  t.end();
});

test('creates a session on a GET request', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfPlugin, {Session});

  const ctx = await request(app, '/');
  t.notok(
    ctx.response.headers['x-csrf-token'],
    'does not set x-csrf-token header'
  );
  t.equals(ctx.response.status, 200, 'has right status');
  t.ok(Session.from(ctx).get('csrf-secret'), 'sets the session');
  t.end();
});

test('render request', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfPlugin, {Session});

  const ctx = await render(app, '/');
  t.notok(
    ctx.response.headers['x-csrf-token'],
    'does not set x-csrf-token header'
  );
  t.equals(ctx.response.status, 200, 'has right status');
  t.ok(Session.from(ctx).get('csrf-secret'), 'sets the session');
  t.ok(
    ctx.response.body.includes('<script id="__CSRF_TOKEN__"'),
    'serializes token'
  );
  t.end();
});

test('fails with no session and invalid token', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfPlugin, {Session});

  try {
    await request(app, '/test', {
      method: 'POST',
      headers: {'x-csrf-token': 'invalid'},
    });
    t.fail('should fail');
  } catch (e) {
    t.equal(e.status, 403);
  }

  t.end();
});

test('fails with session and no token', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfPlugin, {Session});

  await request(app, '/csrf-token', {method: 'POST'});

  try {
    await request(app, '/test', {
      method: 'POST',
    });
    t.fail('should fail');
  } catch (e) {
    t.equal(e.status, 403);
  }

  t.end();
});

test('fails with session and invalid token', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfPlugin, {Session});

  await request(app, '/csrf-token', {method: 'POST'});

  try {
    await request(app, '/test', {
      method: 'POST',
      headers: {'x-csrf-token': 'invalid'},
    });
    t.fail('should fail');
  } catch (e) {
    t.equal(e.status, 403);
  }

  t.end();
});

test('fails with expired token', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfPlugin, {Session, expire: 1});

  const ctx = await request(app, '/csrf-token', {method: 'POST'});

  await new Promise(resolve => setTimeout(resolve, 2000));

  try {
    await request(app, '/test', {
      method: 'POST',
      headers: {'x-csrf-token': ctx.response.headers['x-csrf-token']},
    });
    t.fail('should fail');
  } catch (e) {
    t.equal(e.status, 403);
  }

  t.end();
});

test('does not verify ignored paths', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  const CSRF = app.plugin(CsrfPlugin, {Session});
  CSRF.of().ignore('/test');
  const ctx = await request(app, '/test', {
    method: 'POST',
  });
  t.equal(ctx.response.status, 200);
  t.end();
});
