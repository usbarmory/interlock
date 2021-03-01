/** INTERLOCK | https://github.com/f-secure-foundry/interlock
 * Copyright (c) F-Secure Corporation
 *
 * Use of this source code is governed by the license
 * that can be found in the LICENSE file.
 */

/**
 * @namespace
 *
 * @description
 * Interlock application global namespace
*/
var Interlock = {};

function sessionStorageSupported() {
  try {
    return (window.sessionStorage && window.sessionStorage !== null);
  } catch (e) {
    return false;
  }
}

function fileAPISupported() {
  try {
    return (window.File != null && window.FileList != null && window.FileReader != null);
  } catch (e) {
    return false;
  }
}

if (sessionStorageSupported() && fileAPISupported()) {
  /* configure jQuery to add the dataTransfer property to the native
     'drop' event. Used by drag and drop Interlock functionality */
  jQuery.event.props.push( "dataTransfer" );

  Interlock.Modules = {};
  Interlock.Modules.UI = new $.Deferred();
  Interlock.Modules.backend = new $.Deferred();
  Interlock.Modules.session = new $.Deferred();
  Interlock.Modules.config = new $.Deferred();
  Interlock.Modules.LUKS = new $.Deferred();
  Interlock.Modules.fileManager = new $.Deferred();
  Interlock.Modules.crypto = new $.Deferred();
  Interlock.Modules.Signal = new $.Deferred();

  $.getScript('/js/ui.js')
    .done(function(script, textStatus) {
      Interlock.Modules.UI.resolve();
    })
    .fail(function(jqxhr, settings, e) {
        console.log('[Interlock.UI] failed to load module: ' + e + '\n');
  });

  /* backend module depends on UI */
  $.when(Interlock.Modules.UI).done(function() {
    $.getScript('/js/backend.js')
      .done(function(script, textStatus) {
        Interlock.Modules.backend.resolve();
      })
      .fail(function(jqxhr, settings, e) {
          console.log('[Interlock.Backend] failed to load module: ' + e + '\n');
    })
  });

  /* session module depends on UI and backend */
  $.when(Interlock.Modules.UI, Interlock.Modules.backend).done(function() {
    $.getScript('/js/session.js')
      .done(function(script, textStatus) {
        Interlock.Modules.session.resolve();
      })
      .fail(function(jqxhr, settings, e) {
        console.log('[Interlock.Session] failed to load module: ' + e + '\n');
    })
  });

  /* all the remaining Interlock modules depends on UI, backend and session,
     apart from Signal that depends also on crypto and file manager that
     depends on Signal and crypto */
  $.when(Interlock.Modules.UI, Interlock.Modules.backend, Interlock.Modules.session).done(function() {
    $.getScript('/js/config.js')
      .done(function(script, textStatus) {
        Interlock.Modules.config.resolve();
      })
      .fail(function(jqxhr, settings, e) {
        console.log('[Interlock.Config] failed to load module: ' + e + '\n');
    })

    $.getScript('/js/luks.js')
      .done(function(script, textStatus) {
        Interlock.Modules.LUKS.resolve();
      })
      .fail(function(jqxhr, settings, e) {
        console.log('[Interlock.LUKS] failed to load module: ' + e + '\n');
    })

    $.getScript('/js/crypto.js')
      .done(function(script, textStatus) {
        Interlock.Modules.crypto.resolve();
      })
      .fail(function(jqxhr, settings, e) {
        console.log('[Interlock.Crypto] failed to load module: ' + e + '\n');
    })
  });

  /* module Signal depends also on crypto and session */
  $.when(Interlock.Modules.UI, Interlock.Modules.backend, Interlock.Modules.crypto,
         Interlock.Modules.session).done(function() {
    $.getScript('/js/signal.js')
      .done(function(script, Signal) {
        Interlock.Modules.Signal.resolve();
      })
      .fail(function(jqxhr, settings, e) {
          console.log('[Interlock.Signal] failed to load module: ' + e + '\n');
    })
  });

  $.when(Interlock.Modules.UI, Interlock.Modules.backend, Interlock.Modules.crypto,
         Interlock.Modules.session, Interlock.Modules.Signal).done(function() {
    $.getScript('/js/file_manager.js')
      .done(function(script, textStatus) {
        Interlock.Modules.fileManager.resolve();
      })
      .fail(function(jqxhr, settings, e) {
        console.log('[Interlock.FileManager] failed to load module: ' + e + '\n');
    })
  });

  $.when(Interlock.Modules.UI, Interlock.Modules.backend,
         Interlock.Modules.session, Interlock.Modules.config,
         Interlock.Modules.fileManager, Interlock.Modules.LUKS,
         Interlock.Modules.crypto, Interlock.Modules.Signal).done(function() {

    Interlock.Session.createEvent({'kind': 'info',
      'msg': '[Interlock] application modules successfully loaded\n'});

    /* check if a valid XSRFToken and a mounted volume is present in
       the current Interlock.Session */
    if (sessionStorage.XSRFToken && sessionStorage.volume) {
      $.get('/templates/file_manager.html', function(data) {
        $('body').html(data);
        document.title = 'INTERLOCK';

        Interlock.Session.getVersion();
        Interlock.Session.statusPoller();
      });
    } else {
      /* try to refresh the XSRFToken, it will succeed only if a valid
         session cookie is present inthe browser - multiple tabs */
      Interlock.Session.refresh();
    }
  });
} else {
  /* don't load anything if the user browser does not support
     HTML5 file API and/or session storage. Interlock.Session
     notifications are not available here: use alert() */
  alert('INTERLOCK cannot run properly on your browser,\n' +
        'HTML5 file API and/or sessionStorage is not supported.');
}
