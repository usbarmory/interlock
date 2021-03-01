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
 * Signal instance class
 */
Interlock.Signal = new function() {
  /** @private */
  sessionStorage.clipBoard = sessionStorage.clipBoard || JSON.stringify({ 'action': 'none', 'paths': undefined, 'isSingleFile': false });

  /** @protected */
  this.historyPollerInterval = { };
};

/** @public */

/**
 * @function
 * @public
 *
 * @description
 * Opens the Signal chat view
 *
 * @param {string} contact string
 * @returns {}
 */
Interlock.Signal.chat = function(contact) {
  Interlock.Signal.historyPollerInterval[contact] = 0;

  var clipBoard = JSON.parse(sessionStorage.clipBoard);

  var elements = [$(document.createElement('p')).append($(document.createElement('pre')).text('')
                                                                                        .attr('id', 'history')
                                                                                        .attr('spellcheck',false)
                                                                                        .addClass('history_contents')),
                  $(document.createElement('br')),
                  $(document.createElement('textarea')).attr('id', 'msg')
                                                       .attr('name', 'msg')
                                                       .attr('cols', 2)
                                                       .attr('rows', 4)
                                                       .attr('spellcheck',false)
                                                       .attr('placeholder', 'Send Signal message')
                                                       .addClass('text ui-widget-content ui-corner-all key')];

  var buttons = { 'Close': function() {
                    Interlock.Signal.historyPollerInterval[contact] = 0;
                    Interlock.UI.modalFormDialog('close');
                  },
                  'Send': function() {
                    if ($('#msg').val().length > 0) {
                      Interlock.Signal.send(contact, $('#msg').val());
                    }
                  }
                };

  var contactName = contact.split('/').pop().split('.Signal')[0] || 'Unknown Contact';

  /* a single file is present in the copy buffer, enable the
     Send Attachment button */
  if (clipBoard.isSingleFile === true && clipBoard.action === 'copy') {
    var fileName = clipBoard.paths.split('/').pop();
    buttons['Send Attachment: ' + fileName] = function() { Interlock.Signal.send(contact, fileName, clipBoard.paths); };
  } else {
    /* open the help dialog for the Signal send attachment feature */
    buttons['Send Attachment'] = function() { Interlock.Signal.attachmentHelpDialog(); };
  }

  buttons['Verify'] = function() {
    var remote = 'remote_' + contact.split(/\s\+/).pop();
    var key_path = '/' + sessionStorage.InterlockKeyPath + '/signal/private/identity/';
    Interlock.Crypto.keyInfo(key_path + remote);
  };

  Interlock.UI.modalFormConfigure({elements: elements, buttons: buttons,
                                   noCancelButton: true, noCloseButton:true,
                                   submitButton: 'Send', title: contactName,
                                   height: 600, width: 800});

  Interlock.UI.modalFormDialog('open');

  /* starts the history poller */
  Interlock.Signal.historyPollerInterval[contact] = 5000;
  Interlock.Signal.getHistory(contact);
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the chat history according with the data
 * retrieved from the backend
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.Signal.getHistoryCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      /* ensure that the history poller for the selected contact is
         still active before to actually refresh the chat history */
      if (Interlock.Signal.historyPollerInterval[args.contact] > 0) {
        if ($('#history').text() !== backendData.response) {
          if ($('#history').scrollTop() + $('#history').height() === $('#history').prop('scrollHeight')) {
            $('#history').text(backendData.response);
            $('#history').scrollTop($('#history').prop('scrollHeight'));
          } else {
            $('#history').text(backendData.response);
          }
        }
      }
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Signal.getHistoryCallback] ' + backendData.response});

      Interlock.Signal.historyPollerInterval[args.contact] = 0;
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Signal.getHistoryCallback] ' + e});
  } finally {
    $('.ui-dialog > .ajax_overlay').remove();

    if (Interlock.Signal.historyPollerInterval[args.contact] > 0) {
      setTimeout(function(){ Interlock.Signal.getHistory(args.contact); }, Interlock.Signal.historyPollerInterval[args.contact]);
    }
  }
};

/**
 * @function
 * @public
 *
 * @description
 * refresh the chat history, this function implements a similar logic
 * of Interlock.FileManager.fileDownloadView
 *
 * @param {string} contact Signal contact
 * @returns {}
 */
Interlock.Signal.getHistory = function(contact) {
  try {
    /* ensure that the history poller for the selected contact is
         still active before to actually refresh the chat history */
    if (Interlock.Signal.historyPollerInterval[contact] > 0) {
      Interlock.UI.ajaxLoader('.ui-dialog');
      Interlock.Backend.APIRequest(Interlock.Backend.API.Signal.history, 'POST',
        JSON.stringify({contact: contact}), 'Signal.getHistoryCallback',
        null, {contact: contact});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Signal.getHistory] ' + e});
    $('.ui-dialog > .ajax_overlay').remove();
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the chat history according with the data
 * retrieved from the backend, after sending the msg
 *
 * @param {Object} backendData
 * @param {Object} args contact
 * @returns {}
 */
Interlock.Signal.sendCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      $('#msg').val('');
      Interlock.Signal.getHistory(args.contact);

      if (args.attachment === true) {
        /* re-set the dialog if an attachment has been sent */
        Interlock.UI.modalFormDialog('close');
        Interlock.Signal.chat(args.contact);
      }
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Signal.sendCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Signal.sendCallback] ' + e});
  } finally {
    Interlock.Signal.historyPollerInterval[args.contact] = 5000;
    $('.ui-dialog > .ajax_overlay').remove();
  }
};

/**
 * @function
 * @public
 *
 * @description
 * asks to the backend to send a Signal message to the specified
 * contact
 *
 * @param {string} contact
 * @param {string} msg
 * @param {string} attachment file path
 * @returns {}
 */
Interlock.Signal.send = function(contact, msg, attachment) {
  try {
    Interlock.Signal.historyPollerInterval[contact] = 0;
    Interlock.UI.ajaxLoader('.ui-dialog');

    if (attachment !== undefined) {
      Interlock.Backend.APIRequest(Interlock.Backend.API.Signal.send, 'POST',
        JSON.stringify({contact: contact, msg: msg, attachment: attachment}), 'Signal.sendCallback',
        null, {contact: contact, attachment: true});
    } else {
      Interlock.Backend.APIRequest(Interlock.Backend.API.Signal.send, 'POST',
        JSON.stringify({contact: contact, msg: msg}), 'Signal.sendCallback',
        null, {contact: contact, attachment: false});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileDownload] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, 2-step Signal registration - request a new verification code
 * response from the backend
 *
 * @param {Object} backendData
 * @param {Object} args contact and type
 * @returns {}
 */
Interlock.Signal.requestVerifyCodeCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
        Interlock.UI.modalFormDialog('close');

        var elements = [$(document.createElement('input')).attr('id', 'contact')
                                                          .attr('name', 'contact')
                                                          .attr('placeholder', 'phone number with country code (e.g. +123456789)')
                                                          .attr('type', 'text')
                                                          .attr('value', args.contact)
                                                          .attr('disabled', 'true')
                                                          .addClass('text ui-widget-content ui-corner-all'),
                         $(document.createElement('input')).attr('id', 'code')
                                                           .attr('name', 'code')
                                                           .attr('placeholder', 'verification code')
                                                           .attr('type', 'text')
                                                           .attr('value', '')
                                                           .addClass('text ui-widget-content ui-corner-all')];

        var buttons = { 'Register': function() {
            Interlock.Signal.registration($('#contact').val(), $('#code').val())
          }
        };

        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          submitButton: 'Register', title: 'Signal registration (step 2)', height: 250, width: 400 });
        Interlock.UI.modalFormDialog('open');
   } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Signal.verifyCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Signal.verifyCodeCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * 2-step Signal registration - request a new verification code
 *
 * @param {string} contact
 * @param {string} type
 * @returns {}
 */
Interlock.Signal.requestVerifyCode = function(contact, type) {
  try {
    if (contact === '') {
      Interlock.Session.createEvent({'kind': 'critical',
              'msg': '[Interlock.Signal.verifyCode] please insert a valid phone number'});

      return false;
    }

    if (type === '') {
      Interlock.Session.createEvent({'kind': 'critical',
              'msg': '[Interlock.Signal.verifyCode] please choose a verification method'});

      return false;
    }

    Interlock.Backend.APIRequest(Interlock.Backend.API.Signal.register, 'POST',
      JSON.stringify({contact: contact, type: type}), 'Signal.requestVerifyCodeCallback',
      null, {contact: contact, type: type });
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Signal.verifyCode] ' + e});
  }
};


/**
 * @function
 * @public
 *
 * @description
 * Callback function, 2-step Signal registration - registration request
 * response from the backend
 *
 * @param {Object} backendData
 * @param {Object} args contact and type
 * @returns {}
 */
Interlock.Signal.registrationCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
        var msg = 'Finalizing Signal registration, check Application Logs for completion and cipher enabling. ' +
                  'Once registration is complete contacts can be added as directories with path "signal/$name $number", ' +
                  'a chat session can be started using the right click menu on the contact directory.';
        var elements = [$(document.createElement('p')).text(msg)
                                                      .attr('id', 'msg')
                                                      .attr('spellcheck', false)];
        var buttons = { 'OK': function() { Interlock.UI.modalFormDialog('close'); } };

        Interlock.UI.modalFormDialog('close');
        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          title: 'Signal Registration', noCancelButton: true, height: 250, width: 400 });
        Interlock.UI.modalFormDialog('open');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.Signal.registrationCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Signal.registrationCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * 2-step Signal registration - registration request
 *
 * @param {string} contact
 * @param {string} type
 * @returns {}
 */
Interlock.Signal.registration = function(contact, code) {
  try {
    if (code === '') {
      Interlock.Session.createEvent({'kind': 'critical',
              'msg': '[Interlock.Signal.registration] please insert a valid verification code'});

      return false;
    }

    Interlock.Backend.APIRequest(Interlock.Backend.API.Signal.register, 'POST',
      JSON.stringify({contact: contact, code: code}), 'Signal.registrationCallback',
      null, {contact: contact, code: code });
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Signal.registration] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * open the help dialog
 */
Interlock.Signal.attachmentHelpDialog = function() {
  Interlock.Session.createEvent({'kind': 'critical',
    'msg': 'In order to select a file for attachment please select it' +
           ' in the file manager and use the "Copy" action, come back to' +
           ' the chat session to attach it.' });
};
