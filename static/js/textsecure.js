/** INTERLOCK | https://github.com/inversepath/interlock
 * Copyright (c) 2015 Inverse Path S.r.l.
 *
 * Use of this source code is governed by the license
 * that can be found in the LICENSE file.
 */

/**
 * @class
 * @constructor
 *
 * @description
 * TextSecure instance class
 */
Interlock.TextSecure = new function() {
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
 * Opens the TextSecure chat view
 *
 * @param {string} contact string
 * @returns {}
 */
Interlock.TextSecure.chat = function(contact) {
  Interlock.TextSecure.historyPollerInterval[contact] = 0;

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
                                                       .attr('placeholder', 'Send TextSecure message')
                                                       .addClass('text ui-widget-content ui-corner-all key')];

  var buttons = {  'Close': function() {
                     Interlock.TextSecure.historyPollerInterval[contact] = 0;
                     Interlock.UI.modalFormDialog('close');
                   },
                   'Send': function() {
                     if ($('#msg').val().length > 0) {
                       Interlock.TextSecure.send(contact, $('#msg').val())
                     }
                   }
                 };

  var contactName = contact.split('/').pop().split('.textsecure')[0] || 'Unknown Contact';

  /* a single file is present in the copy buffer, enable the
     Send Attachment button */
  if (clipBoard.isSingleFile === true && clipBoard.action === 'copy') {
    var fileName = clipBoard.paths.split('/').pop();
    buttons['Send Attachment: ' + fileName] = function() { Interlock.TextSecure.send(contact, fileName, clipBoard.paths); };
  } else {
    /* open the help dialog for the TextSecure send attachment feature */
    buttons['Send Attachment'] = function() { Interlock.TextSecure.attachmentHelpDialog(); };
  }

  Interlock.UI.modalFormConfigure({elements: elements, buttons: buttons,
                                   noCancelButton: true, submitButton: 'Send',
                                   title: contactName,
                                   height: 600, width: 800});

  Interlock.UI.modalFormDialog('open');

  /* starts the history poller */
  Interlock.TextSecure.historyPollerInterval[contact] = 5000;
  Interlock.TextSecure.getHistory(contact);
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
Interlock.TextSecure.getHistoryCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      /* ensure that the history poller for the selected contact is
         still active before to actually refresh the chat history */
      if (Interlock.TextSecure.historyPollerInterval[args.contact] > 0) {
          $('#history').text(backendData.response);
          $('#history').scrollTop(10000);
      }
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.TextSecure.getHistoryCallback] ' + backendData.response});

      Interlock.TextSecure.historyPollerInterval[args.contact] = 0;
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.TextSecure.getHistoryCallback] ' + e});
  } finally {
    $('.ui-dialog > .ajax_overlay').remove();

    if (Interlock.TextSecure.historyPollerInterval[args.contact] > 0) {
      setTimeout(function(){ Interlock.TextSecure.getHistory(args.contact); }, Interlock.TextSecure.historyPollerInterval[args.contact]);
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
 * @param {string} contact TextSecure contact
 * @returns {}
 */
Interlock.TextSecure.getHistory = function(contact) {
  try {
    /* ensure that the history poller for the selected contact is
         still active before to actually refresh the chat history */
    if (Interlock.TextSecure.historyPollerInterval[contact] > 0) {
      Interlock.UI.ajaxLoader('.ui-dialog');
      Interlock.Backend.APIRequest(Interlock.Backend.API.textsecure.history, 'POST',
        JSON.stringify({contact: contact}), 'TextSecure.getHistoryCallback',
        null, {contact: contact});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.TextSecure.getHistory] ' + e});
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
Interlock.TextSecure.sendCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      $('#msg').val('');
      Interlock.TextSecure.getHistory(args.contact);

      if (args.attachment === true) {
        sessionStorage.clipBoard = JSON.stringify({ 'action': 'none', 'paths': undefined, 'isSingleFile': false });

        /* re-set the dialog if an attachment has been sent */
        Interlock.UI.modalFormDialog('close');
        Interlock.TextSecure.chat(args.contact);
      }
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.TextSecure.sendCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.TextSecure.sendCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * asks to the backend to send a TextSecure message to the specified
 * contact
 *
 * @param {string} contact
 * @param {string} msg
 * @param {string} attachment file path
 * @returns {}
 */
Interlock.TextSecure.send = function(contact, msg, attachment) {
  try {
    if (attachment !== undefined) {
      Interlock.Backend.APIRequest(Interlock.Backend.API.textsecure.send, 'POST',
        JSON.stringify({contact: contact, msg: msg, attachment: attachment}), 'TextSecure.sendCallback',
        null, {contact: contact, attachment: true});
    } else {
      Interlock.Backend.APIRequest(Interlock.Backend.API.textsecure.send, 'POST',
        JSON.stringify({contact: contact, msg: msg}), 'TextSecure.sendCallback',
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
 * open the help dialog
 */
Interlock.TextSecure.attachmentHelpDialog = function() {
  Interlock.Session.createEvent({'kind': 'critical',
    'msg': 'In order to select a file for attachment please select it' +
           ' in the file manager and use the "Copy" action, come back to' +
           ' the chat session to attach it.' });
};
