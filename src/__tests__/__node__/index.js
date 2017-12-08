import test from 'tape-cup';
import CsrfToken from '../../server';
import {request, render} from 'fusion-test-utils';
import App from 'fusion-core';

function getSession() {
  const state = {};
  const Session = {
    of() {
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

test('valid token', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfToken, {Session});

  const ctx = await request(app, '/csrf-token', {method: 'POST'});
  t.ok(ctx.response.headers['x-csrf-token'], 'has token');
  t.equals(ctx.response.status, 200, 'has right status');
  t.equals(ctx.response.body, '', 'has empty body');
  const nextCtx = await request(app, '/test', {
    method: 'POST',
    headers: {
      'x-csrf-token': ctx.response.headers['x-csrf-token'],
    },
  });
  t.equal(nextCtx.response.status, 200);
  t.end();
});

test('creates a session on a GET request', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfToken, {Session});

  const ctx = await request(app, '/');
  t.notok(
    ctx.response.headers['x-csrf-token'],
    'does not set x-csrf-token header'
  );
  t.equals(ctx.response.status, 200, 'has right status');
  t.ok(Session.of(ctx).get('csrf-secret'), 'sets the session');
  t.end();
});

test('render request', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfToken, {Session});

  const ctx = await render(app, '/');
  t.notok(
    ctx.response.headers['x-csrf-token'],
    'does not set x-csrf-token header'
  );
  t.equals(ctx.response.status, 200, 'has right status');
  t.ok(Session.of(ctx).get('csrf-secret'), 'sets the session');
  t.ok(
    ctx.response.body.includes('<script id="__CSRF_TOKEN__"'),
    'serializes token'
  );
  t.end();
});

test('fails with no session and invalid token', async t => {
  const Session = getSession();
  const app = new App('fake-element', el => el);
  app.plugin(CsrfToken, {Session});

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
  app.plugin(CsrfToken, {Session});

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
  app.plugin(CsrfToken, {Session});

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
  app.plugin(CsrfToken, {Session, expire: 1});

  const ctx = await request(app, '/csrf-token', {method: 'POST'});

  await new Promise(resolve => setTimeout(resolve, 2000));

  try {
    const c = await request(app, '/test', {
      method: 'POST',
      headers: {'x-csrf-token': ctx.response.headers['x-csrf-token']},
    });
    t.fail('should fail');
  } catch (e) {
    t.equal(e.status, 403);
  }

  t.end();
});
