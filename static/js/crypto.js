/**
 * @class
 * @constructor
 *
 * @description
 * Crypto instance class
 */
Interlock.Crypto = new function() {
  /** @private */

  /* list containing all the available ciphers */
  var ciphers = [];
  /* list containing all the available keys */
  var keys = [];

  /** @protected */
  this.refreshCiphers = function(newCiphers) {
    ciphers = [];

    $.each(newCiphers, function(index, cipher) {
      /* skip malformed objects */
      if (Interlock.Crypto.isValidCipher(cipher)){
        ciphers.push({ name: cipher.name,
                       info: cipher.info,
                       key_format: cipher.key_format,
                       enc: cipher.enc,
                       dec: cipher.dec,
                       sig: cipher.sig,
                       ext: cipher.ext });
      }
    });
  };

  this.refreshKeys = function(newKeys) {
    keys = [];

    $.each(newKeys, function(index, key) {
      /* skip malformed objects */
      if (Interlock.Crypto.isValidKey(key)) {
        keys.push({ identifier: key.identifier,
                    key_format: key.key_format,
                    cipher: key.cipher,
                    private: key.private,
                    path: key.path });
      }
    });
  };

  this.getCiphers = function() {
    return ciphers;
  }

  this.getPrivateKeys = function() {
    var privateKeys = [];

    $.each(keys, function(index, key) {
      if (key.private) {
        privateKeys.push(key);
      }
    })

    return privateKeys;
  };

  this.getPublicKeys = function() {
    var publicKeys = [];

    $.each(keys, function(index, key) {
      if (!key.private) {
        publicKeys.push(key);
      }
    })

    return publicKeys;
  };
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, populate the crypto cipher list according with the
 * results returned by the backend
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.Crypto.cipherListCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.Crypto.refreshCiphers(backendData.response);
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Crypto.cipherListCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.cipherListCallback] ' + e});
  } finally {
    Interlock.cipherList.resolve();
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Retrieve the available cipher list from the backend
 *
 * @param {}
 * @returns {}
 */
Interlock.Crypto.cipherList = function() {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.ciphers, 'GET',
      null, 'Crypto.cipherListCallback', null);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.cipherList] ' + e});

    Interlock.cipherList.resolve();
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, populate the crypto key list according with the
 * results returned by the backend
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.Crypto.keyListCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.Crypto.refreshKeys(backendData.response);
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Crypto.keyListCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.keyListCallback] ' + e});
  } finally {
    Interlock.keyList.resolve();
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Retrieve the available key list from the backend
 *
 * @returns {}
 */
Interlock.Crypto.keyList = function() {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.keys, 'POST',
      JSON.stringify({private: true, public: true}), 'Crypto.keyListCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.keyList] ' + e});

    Interlock.keyList.resolve();
  }
};

/**
 * @function
 * @public
 *
 * @description
 * basic key format validation
 *
 * @returns {}
 */
Interlock.Crypto.isValidKey = function(key) {
  var valid = true;

  valid = valid &&
    (key.identifier !== undefined &&
     key.key_format !== undefined &&
     key.cipher !== undefined &&
     key.private !== undefined &&
     key.path !== undefined);

  return valid;
};

/**
 * @function
 * @public
 *
 * @description
 * basic cipher format validation
 *
 * @returns {}
 */
Interlock.Crypto.isValidCipher = function(cipher) {
  var valid = true;

  valid = valid &&
    (cipher.name !== undefined &&
     cipher.info !== undefined &&
     cipher.key_format !== undefined &&
     cipher.enc !== undefined &&
     cipher.dec !== undefined &&
     cipher.sig !== undefined &&
     cipher.ext !== undefined);

  return valid;
};
