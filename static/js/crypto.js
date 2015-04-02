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
    });

    return privateKeys;
  };

  this.getPublicKeys = function() {
    var publicKeys = [];

    $.each(keys, function(index, key) {
      if (!key.private) {
        publicKeys.push(key);
      }
    });

    return publicKeys;
  };

  this.getSignKeys = function() {
    var signKeys = [];
    var privateKeys = this.getPrivateKeys();

    $.each(privateKeys, function(indexKey, key) {
      $.each(ciphers, function(indexCipher, cipher) {
        if (key.cipher === cipher.name && cipher.sig === true) {
          signKeys.push(key);
        }
      });
    });

    return signKeys;
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
 * Callback function, get key information
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.Crypto.keyInfoCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      var elements = [];
      var buttons = {'OK': function() { Interlock.UI.modalFormDialog('close'); } };

      $.each(backendData.response.split(/\n/), function(index, line) {
        var pEl = $(document.createElement('p'));

        if (line.match(/\s\s/)) {
          pEl.addClass('indent');
        }

        elements.push(pEl.text(line));
      });

      Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons, title: 'Key Info', noCancelButton: true, height: 500, width: 500 });
      Interlock.UI.modalFormDialog('open');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Crypto.keyInfoCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.keyInfoCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Retrieve key information
 *
 * @param {String} path, key path
 * @returns {}
 */
Interlock.Crypto.keyInfo = function(path) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.keyInfo, 'POST',
      JSON.stringify({path: path}), 'Crypto.keyInfoCallback', null);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.keyInfo] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, upload a new key
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.Crypto.uploadKeyCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');

      /* reload of the file list should be conditional: only if the
         current pwd is a key path */
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Crypto.uploadKeyCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.uploadKeyInfoCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Upload a new key
 *
 * @param {String} key, data
 * @returns {}
 */
Interlock.Crypto.uploadKey = function(key, data) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.uploadKey, 'POST',
      JSON.stringify({key: key, data: data}), 'Crypto.uploadKeyCallback', null);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.uploadKey] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, generate a new key
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.Crypto.generateKeyCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');

      /* reload of the file list should be conditional: only if the
         current pwd is a key path */
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Crypto.generateKeyCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.generateKeyInfoCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Generate a new key
 *
 * @param {String} key identifier, cipher, key_format, email
 * @returns {}
 */
Interlock.Crypto.generateKey = function(key) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.generateKey, 'POST',
      JSON.stringify({identifier: key.identifier, cipher: key.cipher, key_format: key.key_format, email: key.email}),
        'Crypto.generateKeyCallback', null);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.generateKey] ' + e});
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
