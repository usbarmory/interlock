/** INTERLOCK | https://github.com/f-secure-foundry/interlock
 * Copyright (c) F-Secure Corporation
 *
 * Use of this source code is governed by the license
 * that can be found in the LICENSE file.
 */

/**
 * @class
 * @constructor
 *
 * @description
 * Backend instance class
 */
Interlock.Backend = new function() {
  /** @private */

  /** @protected */
  this.API = {
               'auth':       { 'login':    'auth/login',
                               'logout':   'auth/logout',
                               'refresh':  'auth/refresh',
                               'powerOff': 'auth/poweroff' },

               'LUKS':       { 'addPwd':    'luks/add',
                               'changePwd': 'luks/change',
                               'removePwd': 'luks/remove'  },

               'file':       { 'list':     'file/list',
                               'upload':   'file/upload',
                               'download': 'file/download',
                               'delete':   'file/delete',
                               'move':     'file/move',
                               'copy':     'file/copy',
                               'mkdir':    'file/mkdir',
                               'encrypt':  'file/encrypt',
                               'decrypt':  'file/decrypt',
                               'verify':   'file/verify',
                               'sign':     'file/sign',
                               'extract':  'file/extract',
                               'compress': 'file/compress',
                               'newfile':  'file/new' },

               'crypto':     { 'ciphers':     'crypto/ciphers',
                               'keys':        'crypto/keys',
                               'generateKey': 'crypto/gen_key',
                               'uploadKey':   'crypto/upload_key',
                               'keyInfo':     'crypto/key_info' },

               'config':     { 'time': 'config/time' },

               'status':     { 'version': 'status/version',
                               'running': 'status/running' },

               'Signal': { 'send':     'Signal/send',
                           'history':  'Signal/history',
                           'register': 'Signal/register' }
             };

  this.API.prefix = '/api/';
};

/**
 * @function
 * @public
 *
 * @description
 * Sends a generic JSON payload to the backend, takes as arguments
 * the callback functions for the 'done' or 'fail' conditions.
 *
 * This function is not protected against exceptions, it should be
 * always invoked inside a try/catch statement.
 *
 * @param {string} APIMethod backend API method
 * @param {string} HttpMethod request HTTP method ('POST'|'GET')
 * @param {string} payload JSON string containing the request payload
 * @param {string} [doneCallback] in the format ClassName.functionName
 * @param {string} [failCallback] in the format ClassName.functionName
 * @param {string} [callbackView] name of the attached view, used by
                                  Classes that supports multiple views
                                  (eg. FileManager)
 * @returns {}
 */
Interlock.Backend.APIRequest = function(APIMethod, HttpMethod, payload, doneCallback, failCallback, callbackView) {
  var doneCallbackClass  = doneCallback ? doneCallback.split('.')[0] : null;
  var doneCallbackMethod = doneCallback ? doneCallback.split('.')[1] : null;
  var failCallbackClass  = failCallback ? failCallback.split('.')[0] : null;
  var failCallbackMethod = failCallback ? failCallback.split('.')[1] : null;

  var jqxhr = $.ajax(
  {
    type: HttpMethod,
    url: Interlock.Backend.API.prefix + APIMethod,
    data: payload,
    processData: false,
    contenType: 'application/json; charset=UTF-8',
    /* XSRF protection: append the X-XSRFToken header to the request */
    beforeSend: function(request) {
      if (Interlock.Session) {
        request.setRequestHeader('X-XSRFToken', sessionStorage.XSRFToken);
      }
    }
  })
  .done(function(msg) {
    if (Interlock.Backend.isValidResponse(msg) === true) {
      if (doneCallbackClass && doneCallbackMethod) {
        if (callbackView) {
          window.Interlock[doneCallbackClass][doneCallbackMethod](msg, callbackView);
        } else {
          window.Interlock[doneCallbackClass][doneCallbackMethod](msg);
        }
      }
    } else {
      Interlock.Session.createEvent({'kind': 'critical',
        'msg': '[Interlock.Backend.APIRequest] invalid backend response'});
    }
  })
  .fail(function() {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Backend.APIRequest] request failed, invalid backend response'});

    if (failCallbackClass && failCallbackMethod) {
      if (callbackView) {
        window.Interlock[failCallbackClass][failCallbackMethod](callbackView);
      } else {
        window.Interlock[failCallbackClass][failCallbackMethod]();
      }
    }
  })
  .always(function(msg) {
  });
};

/**
 * @function
 * @public
 *
 * @description
 * Basic validation of the backend response format. The response
 * must always contain both the 'status' and the 'response' key.
 * 'status' must be OK|KO|INVALID|INVALID_SESSION.
 *
 * @param {Object} backendData
 * @returns {boolean} validationResult
 */
Interlock.Backend.isValidResponse = function(backendData) {
  var valid = true;

  valid = valid && (backendData.status === 'OK' ||
                    backendData.status === 'KO' ||
                    backendData.status === 'INVALID' ||
                    backendData.status === 'INVALID_SESSION');

  valid = valid && (backendData.response !== undefined);

  return valid;
};
