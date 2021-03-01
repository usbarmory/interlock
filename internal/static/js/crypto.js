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
                       otp: cipher.otp,
                       msg: cipher.msg,
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

  this.hasCipher = function(name) {
    var cipherFound = false;

    $.each(ciphers, function(index,cipher) {
      if (cipher.name === name) {
        cipherFound = true;

        /* force exit from $.each() */
        return true;
      }
    });

    return cipherFound;;
  };

  this.getCipherExt = function(name) {
    ext = '';

    $.each(ciphers, function(index,cipher) {
      if (cipher.name === name) {
        ext = cipher.ext;
      }
    });

    return ext;
  };

  this.getCiphers = function(name) {
    selectedCiphers = [];

    if (name) {
      $.each(ciphers, function(index,cipher) {
        if (cipher.name === name) {
          selectedCiphers.push(cipher);
        }
      });
    } else {
      selectedCiphers = ciphers;
    }

    return selectedCiphers;
  };

  this.getEncryptCiphers = function(name) {
    selectedCiphers = [];

    $.each(ciphers, function(index,cipher) {
      if (cipher.enc === true) {
        if (name) {
          if (cipher.name === name) {
            selectedCiphers.push(cipher);
          }
        } else {
          selectedCiphers.push(cipher);
        }
      }
    });

    return selectedCiphers;
  };

  this.getDecryptCiphers = function(name) {
    selectedCiphers = [];

    $.each(ciphers, function(index,cipher) {
      if (cipher.dec === true) {
        if (name) {
          if (cipher.name === name) {
            selectedCiphers.push(cipher);
          }
        } else {
          selectedCiphers.push(cipher);
        }
      }
    });

    return selectedCiphers;
  };

  this.getSignCiphers = function(name) {
    selectedCiphers = [];

    $.each(ciphers, function(index,cipher) {
      if (cipher.sig === true) {
        if (name) {
          if (cipher.name === name) {
            selectedCiphers.push(cipher);
          }
        } else {
          selectedCiphers.push(cipher);
        }
      }
    });

    return selectedCiphers;
  };

  this.getPrivateKeys = function() {
    var privateKeys = [];

    $.each(keys, function(index, key) {
      if (key.private === true) {
        privateKeys.push(key);
      }
    });

    return privateKeys;
  };

  this.getPublicKeys = function() {
    var publicKeys = [];

    $.each(keys, function(index, key) {
      if (key.private === false) {
        publicKeys.push(key);
      }
    });

    return publicKeys;
  };

  this.getEncryptKeys = function() {
    var encryptKeys = [];
    var publicKeys = this.getPublicKeys();

    $.each(publicKeys, function(indexKey, key) {
      $.each(ciphers, function(indexCipher, cipher) {
        if (key.cipher === cipher.name && cipher.enc === true) {
          encryptKeys.push(key);
        }
      });
    });

    return encryptKeys;
  };

  this.getDecryptKeys = function() {
    var decryptKeys = [];
    var privateKeys = this.getPrivateKeys();

    $.each(privateKeys, function(indexKey, key) {
      $.each(ciphers, function(indexCipher, cipher) {
        if (key.cipher === cipher.name && cipher.dec === true) {
          decryptKeys.push(key);
        }
      });
    });

    return decryptKeys;
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

  this.getVerifyKeys = function() {
    var verifyKeys = [];
    var publicKeys = this.getPublicKeys();

    $.each(publicKeys, function(indexKey, key) {
      $.each(ciphers, function(indexCipher, cipher) {
        if (key.cipher === cipher.name && cipher.sig === true) {
          verifyKeys.push(key);
        }
      });
    });

    return verifyKeys;
  };

  this.getKeyCipher = function(identifier) {
   var cipher = '';

    $.each(keys, function(indexKey, key) {
      if (key.identifier === identifier) {
        cipher = key.cipher;
      }
    });

    return cipher;
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
    Interlock.Crypto.cipherListCompleted.resolve();
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
  Interlock.Crypto.cipherListCompleted = new $.Deferred();

  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.ciphers, 'GET',
      null, 'Crypto.cipherListCallback', null);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.cipherList] ' + e});

    Interlock.Crypto.cipherListCompleted.resolve();
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
    Interlock.Crypto.keyListCompleted.resolve();
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
  Interlock.Crypto.keyListCompleted = new $.Deferred();

  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.keys, 'POST',
      JSON.stringify({private: true, public: true}), 'Crypto.keyListCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Crypto.keyList] ' + e});

    Interlock.Crypto.keyListCompleted.resolve();
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
 * @param {Object} commandArguments path, cipher
 * @returns {}
 */
Interlock.Crypto.keyInfoCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      var elements = [];
      var buttons = {};
      var ciphers;

      if (args.cipher) {
        ciphers = Interlock.Crypto.getCiphers(args.cipher);
      }

      /* if key.cipher is otp use UI.modalForm instead of
         UI.notificationForm, and add the Refresh button */
      if (ciphers && ciphers[0] && ciphers[0].otp) {
        buttons = {'OK': function() { Interlock.UI.modalFormDialog('close'); } };

        $.extend(buttons, {'Refresh': function() {
          Interlock.UI.modalFormDialog('close');
          Interlock.Crypto.keyInfo(args.path, args.cipher);
        }});

        $.each(backendData.response.split(/\n/), function(index, line) {
          var pElement = $(document.createElement('p'));

          if (line.match(/\s\s/)) {
            pElement.addClass('indent');
          }

          elements.push(pElement.text(line));
        });

        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          title: 'Key Info', noCancelButton: true, height: 500, width: 500 });
        Interlock.UI.modalFormDialog('open');
      } else {
        buttons = {'OK': function() { Interlock.UI.notificationFormDialog('close'); } };

        $.each(backendData.response.split(/\n/), function(index, line) {
          var pElement = $(document.createElement('p'));

          if (line.match(/\s\s/)) {
            pElement.addClass('indent');
          }

          elements.push(pElement.text(line));
        });

        Interlock.UI.notificationFormDialog({ elements: elements,
          height: 500, width: 500, title: 'Key Info' });
      }
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
 * @param {String} cipher, key cipher
 *
 * @returns {}
 */
Interlock.Crypto.keyInfo = function(path, cipher) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.crypto.keyInfo, 'POST',
      JSON.stringify({path: path}), 'Crypto.keyInfoCallback', null, {path: path, cipher: cipher});
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
     cipher.otp !== undefined &&
     cipher.msg !== undefined &&
     cipher.ext !== undefined);

  return valid;
};
