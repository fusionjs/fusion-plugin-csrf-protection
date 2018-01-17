// @flow
/* eslint-env browser */
import {unescape, withDependencies} from 'fusion-core';
import {verifyMethod, verifyExpiry, CSRFTokenExpire} from './shared';
import {FetchToken} from 'fusion-types';

const BrowserCSRFPlugin = withDependencies({
  fetch: FetchToken,
  expire: CSRFTokenExpire,
})(({fetch, expire}) => {
  // TODO: How does route prefix fit into this?
  const prefix = window.__ROUTE_PREFIX__ || ''; // created by fusion-core/src/server
  const tokenElement = document.getElementById('__CSRF_TOKEN__');

  let token = tokenElement
    ? JSON.parse(unescape(tokenElement.textContent))
    : '';

  function fetchWithCsrfToken(url, options = {}) {
    const isCsrfMethod = verifyMethod(options.method || 'GET');
    const isValid = verifyExpiry(token, expire);
    const isTokenRequired = !isValid || !token;
    if (isCsrfMethod && isTokenRequired) {
      // TODO(#3) don't append prefix if injected fetch also injects prefix
      return fetch(prefix + '/csrf-token', {
        method: 'POST',
        credentials: 'same-origin',
      }).then(r => {
        token = r.headers.get('x-csrf-token');
        return request();
      });
    } else {
      return request();
    }

    function request() {
      return fetch(prefix + url, {
        ...options,
        credentials: 'same-origin',
        headers: {
          ...(options.headers || {}),
          'x-csrf-token': token,
        },
      });
    }
  }
  return fetchWithCsrfToken;
});

export default BrowserCSRFPlugin;
