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
 * Config instance class
 */
Interlock.Config = new function() {
  /** @private */

  /** @protected */
};

/**
 * @function
 * @public
 *
 * @description
 * Set device time according to the host clock
 *
 * @param {}
 * @returns {}
 */
Interlock.Config.setTime = function() {
  try {
    var timeNow = Math.floor((new Date).getTime() / 1000);

    Interlock.Backend.APIRequest(Interlock.Backend.API.config.time, 'POST',
      JSON.stringify({ epoch: timeNow }), 'Config.setTimeCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Config.setTime] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, log the the response from the backend and the
 * error if any
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.Config.setTimeCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.Session.createEvent({'kind': 'info',
        'msg': '[Interlock.Config.setTimeCallback] clock has been succesfully set'});
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Config.setTimeCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Config.setTime] ' + e});
  }
};
