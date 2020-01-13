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
 * LUKS instance class
 */
Interlock.LUKS = new function() {
  /** @private */
  /** @public */
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, reports errors in relationship with the LUKS
 * add password operation
 *
 * @param {Object} backendData
 * @param {Object} commandArguments
 * @returns {}
 */
Interlock.LUKS.addPwdCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
                                     'msg': '[Interlock.LUKS.addPwdCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg': '[Interlock.LUKS.addPwdCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Add a new LUKS password to the next available LUKS slot
 *
 * @param {string} args: volume, password, newpassword
 * @returns {}
 */
Interlock.LUKS.addPwd = function(args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.LUKS.addPwd, 'POST',
      JSON.stringify({volume: args.volume, password: args.password, newpassword: args.newpassword}),
      'LUKS.addPwdCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg': '[Interlock.LUKS.addPwd] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, reports errors in relationship with the LUKS
 * remove password operation
 *
 * @param {Object} backendData
 * @param {Object} commandArguments
 * @returns {}
 */
Interlock.LUKS.removePwdCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
                                     'msg': '[Interlock.LUKS.removePwdCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg': '[Interlock.LUKS.removePwdCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Remove a LUKS password from a LUKS slot
 *
 * @param {string} args: volume, password
 * @returns {}
 */
Interlock.LUKS.removePwd = function(args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.LUKS.removePwd, 'POST',
      JSON.stringify({volume: args.volume, password: args.password}),
      'LUKS.removePwdCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg': '[Interlock.LUKS.removePwd] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, reports errors in relationship with the LUKS
 * change password operation
 *
 * @param {Object} backendData
 * @param {Object} commandArguments
 * @returns {}
 */
Interlock.LUKS.changePwdCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
                                     'msg': '[Interlock.LUKS.changePwdCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg': '[Interlock.LUKS.changePwdCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Change an existing password from a LUKS key slot
 *
 * @param {Object} args: volume, password, newpassword
 * @returns {}
 */
Interlock.LUKS.changePwd = function(args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.LUKS.changePwd, 'POST',
      JSON.stringify({volume: args.volume, password: args.password, newpassword: args.newpassword}),
      'LUKS.changePwdCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg': '[Interlock.LUKS.changePwd] ' + e});
  }
};
