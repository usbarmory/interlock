/**
 * @class
 * @constructor
 *
 * @description
 * FileManager instance class
 */
Interlock.FileManager = new function() {
  /** @private */
  var cache = { 'mainView': [], 'browsingView': [] };

  var SUPPORTED_ARCHIVE_EXTENSIONS = ['zip','ZIP'];

  /* set default pwd and sorting rule for the main file manager
     and the browsing view */
  sessionStorage.mainViewPwd = sessionStorage.mainViewPwd || '/';
  sessionStorage.mainViewSortAttribute = sessionStorage.mainViewSortAttribute || 'name';
  sessionStorage.mainViewSortAsc = sessionStorage.mainViewSortAsc || true;

  sessionStorage.browsingViewPwd = '/';
  sessionStorage.browsingViewSortAttribute = 'name';
  sessionStorage.browsingViewSortAsc = true;
  var MAX_VIEW_SIZE = 1 * 1024 * 1024;

  /** @protected */
  /* FileManager mainView initialization: register drag and drop and
     file/directory upload button event handlers */
  this.init = function() {
    var $fileSelect = $('#fileselect');
    var $directorySelect = $('#directoryselect');
    var $entityDrag = $('.entitydrag');
    var $submitButton = $('#submitbutton');
    var xhr = new XMLHttpRequest();

    $fileSelect.on('change', function(e) { Interlock.FileManager.selectButtonHandler(e); });
    $directorySelect.on('change', function(e) { Interlock.FileManager.selectButtonHandler(e); });

    /* hide the submit button and enable drag and drop events only for
       browsers that supports it */
    if (xhr.upload) {
      $entityDrag.on('dragover', function(e) { Interlock.FileManager.entityDragHover(e); });
      $entityDrag.on('dragleave', function(e) { Interlock.FileManager.entityDragHover(e); });
      $entityDrag.on('drop', function(e) { Interlock.FileManager.entitySelectHandler(e); });

      $entityDrag.css({display: 'block'});
      $submitButton.css({display: 'none'});
    }

    /* remove the context menu on when the user clicks the left button */
    $(document).on('click', function(e) {
      $('ul.inode_menu').remove();
    });

    /* register the on 'click' event to the new directory button */
    $('#add_new_directory').on('click', function() {
      var buttons = { 'Create directory': function() { Interlock.FileManager.mkdir($('#directory').val());} };
      var elements = [$(document.createElement('input')).attr('id', 'directory')
                                                        .attr('name', 'directory')
                                                        .attr('placeholder', 'directory name')
                                                        .attr('type', 'text')
                                                        .addClass('text ui-widget-content ui-corner-all')];

      Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
        submitButton: 'Create directory', title: 'Create new directory' });
      Interlock.UI.modalFormDialog('open');
    });

    /* register the on 'click' event to the new key button */
    $('#import_key').on('click', function() {
      var $selectCiphers = $(document.createElement('select')).attr('id', 'cipher')
                                                              .attr('name', 'cipher');

      var $availableCiphers = [$(document.createElement('option')).attr('value', '')
                                                                  .text('choose encryption cipher')];

      var buttons = { 'Import key': function() {
        Interlock.Crypto.uploadKey({ identifier: $('#identifier').val(),
                                     key_format: $('#key_format').val(),
                                     cipher: $('#cipher').val(),
                                     private: $('#private').is(':checked')},
                                   $('#data').val())
        }
      };

      Interlock.cipherList = new $.Deferred();

      Interlock.Crypto.cipherList();

      /* waits until cipher list have been filled with the backend data */
      $.when(Interlock.cipherList).done(function () {
        $.each(Interlock.Crypto.getCiphers(), function(index, cipher) {
          /* adds only ciphers that support armor as key format */
          if (cipher.key_format !== 'password') {
            $availableCiphers.push($(document.createElement('option')).attr('value', cipher.name)
                                                                      .text(cipher.name));
          }
        });

        $selectCiphers.append($availableCiphers);
      });

      var elements = [$selectCiphers,
                      $(document.createElement('input')).attr('id', 'identifier')
                                                        .attr('name', 'identifier')
                                                        .attr('placeholder', 'key identifier')
                                                        .attr('type', 'text')
                                                        .addClass('text ui-widget-content ui-corner-all'),
                      $(document.createElement('textarea')).attr('id', 'data')
                                                           .attr('name', 'data')
                                                           .attr('cols', 70)
                                                           .attr('rows', 20)
                                                           .attr('spellcheck',false)
                                                           .attr('placeholder', 'key - armor format')
                                                           .addClass('text ui-widget-content ui-corner-all key'),
                      $(document.createElement('input')).attr('id', 'private')
                                                        .attr('name', 'private')
                                                        .attr('placeholder', 'private')
                                                        .attr('type', 'checkbox')
                                                        .addClass('text ui-widget-content ui-corner-all'),
                      $(document.createElement('label')).text('private (leave it unchecked for public key)')
                                                        .attr('for', 'private'),
                      /* FIXME: armor hardcoded in key_format */
                      $(document.createElement('input')).attr('id', 'key_format')
                                                        .attr('name', 'key_format')
                                                        .attr('placeholder', 'key format')
                                                        .attr('type', 'text')
                                                        .attr('value', 'armor')
                                                        .addClass('text ui-widget-content ui-corner-all')
                                                        .hide()];

      Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
        submitButton: 'Import key', title: 'Import a new key', height: 600, width: 550 });
      Interlock.UI.modalFormDialog('open');
    });

    /* register the on 'click' event to the generate new key button */
    $('#generate_key').on('click', function() {
      var $selectCiphers = $(document.createElement('select')).attr('id', 'cipher')
                                                              .attr('name', 'cipher');

      var $availableCiphers = [$(document.createElement('option')).attr('value', '')
                                                                  .text('choose encryption cipher')];

      var buttons = { 'Generate key': function() {
        Interlock.Crypto.generateKey({ identifier: $('#identifier').val(),
                                       cipher: $('#cipher').val(),
                                       key_format: $('#key_format').val(),
                                       email: $('#email').val() })
        }
      };

      Interlock.cipherList = new $.Deferred();

      Interlock.Crypto.cipherList();

      /* waits until cipher list have been filled with the backend data */
      $.when(Interlock.cipherList).done(function () {
        $.each(Interlock.Crypto.getCiphers(), function(index, cipher) {
          /* adds only ciphers that support armor as key format */
          if (cipher.key_format !== 'password') {
            $availableCiphers.push($(document.createElement('option')).attr('value', cipher.name)
                                                                      .text(cipher.name));
          }
        });

        $selectCiphers.append($availableCiphers);
      });

      var elements = [$selectCiphers,
                      $(document.createElement('input')).attr('id', 'identifier')
                                                        .attr('name', 'identifier')
                                                        .attr('placeholder', 'key identifier')
                                                        .attr('type', 'text')
                                                        .addClass('text ui-widget-content ui-corner-all'),
                      $(document.createElement('input')).attr('id', 'email')
                                                        .attr('name', 'email')
                                                        .attr('placeholder', 'email')
                                                        .attr('type', 'text')
                                                        .addClass('text ui-widget-content ui-corner-all'),
                      /* FIXME: armor hardcoded in key_format */
                      $(document.createElement('input')).attr('id', 'key_format')
                                                        .attr('name', 'key_format')
                                                        .attr('placeholder', 'key format')
                                                        .attr('type', 'text')
                                                        .attr('value', 'armor')
                                                        .addClass('text ui-widget-content ui-corner-all')
                                                        .hide()];

      Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
        submitButton: 'Generate key', title: 'Generate a new key', });
      Interlock.UI.modalFormDialog('open');
    });
  };

  /* updates the disk usage info */
  this.refreshDiskUsage = function(totalSpace, freeSpace) {
    var $diskUsageSelector = $('#disk_usage');
    var freeSpace = parseFloat(freeSpace / (1000 * 1000 * 1000)).toFixed(2);
    var totalSpace = parseFloat(totalSpace / (1000 * 1000 * 1000)).toFixed(2);

    $diskUsageSelector.text(freeSpace + ' GB free (' + totalSpace + ' GB total)' );
  }

  this.refreshView = function(view, inodes) {
    var inodes = Interlock.FileManager.sortInodes(inodes);
    var traversingPath = '/';
    var $inodesTable = $('#file_manager_' + view + ' > div.inodes_table_container > table > tbody.inodes_container');
    var $pwd = $('#file_manager_' + view + ' > span.pwd');

    $pwd.html('');
    $inodesTable.html('');

    /* insert the volume name as first element of the pwd browsing bar */
    $(document.createElement('span')).text(sessionStorage.volume || 'InterlockVolume')
                                     .addClass('volumeName')
                                     .appendTo($pwd)
                                     .click(function() {
                                       Interlock.FileManager.fileList(view, '/');
                                     });

    /* updates the pwd browsing links */
    $.each(sessionStorage[view + 'Pwd'].split('/'), function(index, directory) {
      if (directory) {
        traversingPath += directory;
        var $pwdNested = $(document.createElement('span'));
        var path = traversingPath;

        $pwd.append('&nbsp; &#9656; &nbsp;');
        $pwdNested.text(directory)
                  .appendTo($pwd)
                  .click(function() {
                    Interlock.FileManager.fileList(view, path);
                  });

        traversingPath += '/';
      }
    });

    /* refresh file/directory table */
    $.each(inodes, function(index, inode) {
      /* don't show files in the browsingView */
      if (view === 'browsingView' && inode.dir !== true) {
        /* equivalent to continue inside a jQuery .each() loop */
        return;
      }

      var size = Interlock.UI.formatSize(inode.size) || 0;
      var mtime = inode.mtime || 0;
      var path = sessionStorage[view + 'Pwd'] + (sessionStorage[view + 'Pwd'].slice(-1) === '/' ? '' : '/') + inode.name;

      var $inode = $(document.createElement('tr'));
      var $inodeName = $(document.createElement('td')).text(inode.name);
      var $inodeSize = $(document.createElement('td')).text(size);
      var $inodeMtime = $(document.createElement('td')).text(Interlock.UI.convertToTimeString(mtime));

      $inode.append($inodeName, $inodeSize, $inodeMtime)
            .appendTo($inodesTable);

      if (inode.dir) {
        $inode.addClass('directory');
        $inodeName.click(function() {
          Interlock.FileManager.fileList(view, path);
        });
      } else {
        $inode.addClass('file');
      }

      /* open the context menu on right click on the inode (mainView only) */
      if (view === 'mainView') {
        $inode.on('contextmenu', function(e) { Interlock.FileManager.contextMenu(e, inode, path) });
      }
    });
  };

  /* dinamically creates the context menu for every inode entry in the
     File Manager mainView */
  this.contextMenu = function(e, inode, path) {
    e.preventDefault();
    $('ul.inode_menu').remove();

    var menuEntries = [];
    var contextMenu = $(document.createElement('ul')).addClass('inode_menu')
                                                     .appendTo('body')
                                                     .css({top: e.pageY + 'px', left: e.pageX + 'px'});

    /* disable move/copy for every key file or directory */
    if (inode.private) {
      menuEntries.push($(document.createElement('li')).text('Copy')
                                                      .addClass('disabled'));

      menuEntries.push($(document.createElement('li')).text('Move')
                                                      .addClass('disabled'));

      menuEntries.push($(document.createElement('li')).text('Compress')
                                                      .addClass('disabled'));
    } else {
      menuEntries.push($(document.createElement('li')).text('Copy')
                                                      .click(function() {
        var buttons = { 'Copy': function() { Interlock.FileManager.fileCopy({ src: path, dst: $('#dst').val() }) } };

        var elements = [$(document.createElement('p')).text('Destination file or directory (absolute path):')
                                                      .addClass('text ui-widget-content ui-corner-all'),
                        $(document.createElement('input')).attr('id', 'dst')
                                                          .attr('name', 'dst')
                                                          .attr('value', path + '.copy')
                                                          .attr('type', 'text')
                                                          .attr('placeholder', 'destination file or directory')
                                                          .addClass('text ui-widget-content ui-corner-all')];

        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          submitButton: 'Copy', title: 'Copy' });
        Interlock.UI.modalFormDialog('open');
      }));

      menuEntries.push($(document.createElement('li')).text('Move')
                                                      .click(function() {
        var buttons = { 'Move': function() { Interlock.FileManager.fileMove({ src: path, dst: $('#dst').val() }) } };

        var elements = [$(document.createElement('p')).text('Destination file or directory (absolute path):')
                                                      .addClass('text ui-widget-content ui-corner-all'),
                        $(document.createElement('input')).attr('id', 'dst')
                                                          .attr('name', 'dst')
                                                          .attr('value', path + '.moved')
                                                          .attr('type', 'text')
                                                          .attr('placeholder', 'destination file or directory')
                                                          .addClass('text ui-widget-content ui-corner-all')];

        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          submitButton: 'Move', title: 'Move' });
        Interlock.UI.modalFormDialog('open');
      }));
    }

    menuEntries.push($(document.createElement('li')).text('Delete')
                                                    .click(function() {
      var buttons = { 'Delete': function() { Interlock.FileManager.fileDelete([path]) } };

      var elements = [$(document.createElement('p')).text('Are you sure you want to delete the following ' +
                                                         (inode.dir ? 'directories:' : 'files:'))
                                                    .addClass('text ui-widget-content ui-corner-all'),
                      $(document.createElement('p')).text(inode.name)
                                                    .addClass('text ui-widget-content ui-corner-all')];

      Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
        submitButton: 'Delete', title: 'Delete', height: 400, width: 400 });
      Interlock.UI.modalFormDialog('open');
    }));

    if (inode.dir) {
      if (inode.private) {
        menuEntries.push($(document.createElement('li')).text('Compress')
                                                        .addClass('disabled'));
        menuEntries.push($(document.createElement('li')).text('Download (zip archive)')
                                                        .addClass('disabled'));
      } else {
        /* add the compress action for directories */
        /* FIXME: the context menu actions should be conditionally appended
           in a more clean way in order to avoid code repetition */
        menuEntries.push($(document.createElement('li')).text('Compress')
                                                        .click(function() {
          var buttons = { 'Compress': function() { Interlock.FileManager.fileCompress({ src: path, dst: $('#dst').val() }) } };

          var elements = [$(document.createElement('p')).text('Destination archive (absolute path):')
                                                        .addClass('text ui-widget-content ui-corner-all'),
                          $(document.createElement('input')).attr('id', 'dst')
                                                            .attr('name', 'dst')
                                                            .attr('value', path + '.zip')
                                                            .attr('type', 'text')
                                                            .attr('placeholder', 'destination archive')
                                                            .addClass('text ui-widget-content ui-corner-all')];
          Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
            submitButton: 'Compress', title: 'Compress' });
          Interlock.UI.modalFormDialog('open');
        }));

        menuEntries.push($(document.createElement('li')).text('Download (zip archive)')
                                                        .click(function() {
                                                          Interlock.FileManager.fileDownload(path);
                                                        }));
      }
    } else {
      /* file encrypt */
      menuEntries.push($(document.createElement('li')).text('Encrypt')
                                                      .click(function() {

        var $selectCiphers = $(document.createElement('select')).attr('id', 'cipher')
                                                                .attr('name', 'cipher');

        var $selectKeys = $(document.createElement('select')).attr('id', 'key')
                                                             .attr('name', 'key');

        var $selectSignKeys = $(document.createElement('select')).attr('id', 'sig_key')
                                                                 .attr('name', 'sig_key');

        var $availableCiphers = [$(document.createElement('option')).attr('value', '')
                                                                    .text('choose encryption cipher')];

        var $availableKeys = [$(document.createElement('option')).attr('value', '')
                                                                 .text('choose encryption key')];

        var $availableSignKeys = [$(document.createElement('option')).attr('value', '')
                                                                     .text('choose signing key')];

        Interlock.keyList = new $.Deferred();
        Interlock.cipherList = new $.Deferred();

        Interlock.Crypto.cipherList();
        Interlock.Crypto.keyList();

        /* waits until cipher and key lists have been filled with the backend data */
        $.when(Interlock.cipherList, Interlock.keyList).done(function () {
          $.each(Interlock.Crypto.getCiphers(), function(index, cipher) {
            $availableCiphers.push($(document.createElement('option')).attr('value', cipher.name)
                                                                      .text(cipher.name));
          });

          $.each(Interlock.Crypto.getPublicKeys(), function(index, key) {
            $availableKeys.push($(document.createElement('option')).attr('value', key.path)
                                                                   .text(key.identifier));
          });

          $.each(Interlock.Crypto.getSignKeys(), function(index, key) {
            $availableSignKeys.push($(document.createElement('option')).attr('value', key.path)
                                                                       .text(key.identifier));
          });

          $selectCiphers.append($availableCiphers);
          $selectKeys.append($availableKeys);
          $selectSignKeys.append($availableSignKeys);

          $selectCiphers.change(function() {
            var selectedCipher = $('#cipher > option:selected').val();

            switch (selectedCipher) {
              case 'AES-256-OFB':
                $('#password').attr('placeholder', 'encryption password').show();
                $('#wipe_src').show();
                $('#wipe_src_label').show();

                $('#key').hide();
                $('#sig_key').hide();
                $('#sign').prop('checked', false).hide();
                $('#sign_label').hide();

                break;
              case 'OpenPGP':
                $('#key').show();
                $('#sign').show();
                $('#sign_label').show();
                $('#wipe_src').show();
                $('#wipe_src_label').show();

                if ($('#sign').is(':checked') === true) {
                  $('#sig_key').show();
                  $('#password').val('')
                                .attr('placeholder', 'key password')
                                .show();
                } else {
                  $('#sig_key').hide();
                  $('#password').val('').hide();
                }

                break;
              default:
                $('#password').val('').hide();
                $('#key').val('').hide();
                $('#sig_key').val('').hide();
                $('#sign').prop('checked', false).hide();
                $('#sign_label').hide();
                $('#wipe_src').prop('checked', false).hide();
                $('#wipe_src_label').hide();
            }
          });

          var buttons = { 'Encrypt': function() {
            Interlock.FileManager.fileEncrypt( path,
                {cipher: $('#cipher').val(), password: $('#password').val(), key: $('#key').val(),
                 sign: $('#sign').is(':checked'), sig_key: $('#sig_key').val(), wipe_src: $('#wipe_src').is(':checked')});
            }
          };

          var elements = [$selectCiphers,
                          $selectKeys,
                          $(document.createElement('fieldset')).addClass('nested')
                                                               .append(
                            $(document.createElement('input')).attr('id', 'wipe_src')
                                                              .attr('name', 'wipe_src')
                                                              .attr('type', 'checkbox')
                                                              .addClass('text ui-widget-content ui-corner-all')
                                                              .hide(),
                            $(document.createElement('label')).attr('id', 'wipe_src_label')
                                                              .attr('name', 'wipe_src_label')
                                                              .attr('for', 'wipe_src')
                                                              .text('delete the original file after encryption')
                                                              .addClass('text ui-widget-content ui-corner-all')
                                                              .hide()),
                          $(document.createElement('fieldset')).addClass('nested')
                                                               .css({'margin-bottom': '15px'})
                                                               .append(
                            $(document.createElement('input')).attr('id', 'sign')
                                                              .attr('name', 'sign')
                                                              .attr('type', 'checkbox')
                                                              .addClass('text ui-widget-content ui-corner-all')
                                                              .change(function() {
                                                                if ($('#sign').is(':checked') === true) {
                                                                  $('#sig_key').show();
                                                                  $('#password').val('')
                                                                                .attr('placeholder', 'sign key password')
                                                                                .show();
                                                                } else {
                                                                  $('#sig_key').hide();
                                                                   $('#password').val('').hide();
                                                                }
                                                              })
                                                              .hide(),
                            $(document.createElement('label')).attr('id', 'sign_label')
                                                              .attr('name', 'sign_label')
                                                              .attr('for', 'sign')
                                                              .text('sign the encrypted file')
                                                              .addClass('text ui-widget-content ui-corner-all')
                                                              .hide()),
                          $selectSignKeys.hide(),
                          $(document.createElement('input')).attr('id', 'password')
                                                            .attr('name', 'password')
                                                            .attr('value', '')
                                                            .attr('type', 'password')
                                                            .attr('placeholder', 'encryption password')
                                                            .addClass('text ui-widget-content ui-corner-all')];

          Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
            submitButton: 'Encrypt', title: 'Encrypt File', height: 380});

          Interlock.UI.modalFormDialog('open');

          $('#password').hide();
          $('#key').hide();
        });
      }));

      /* file decrypt */
      menuEntries.push($(document.createElement('li')).text('Decrypt')
                                                      .click(function() {
        var $selectCiphers = $(document.createElement('select')).attr('id', 'cipher')
                                                                .attr('name', 'cipher');

        var $selectKeys = $(document.createElement('select')).attr('id', 'key')
                                                             .attr('name', 'key');

        var $availableCiphers = [$(document.createElement('option')).attr('value', '')
                                                                    .text('choose decryption cipher')];

        var $availableKeys = [$(document.createElement('option')).attr('value', '')
                                                                 .text('choose decryption key')];

        Interlock.keyList = new $.Deferred();
        Interlock.cipherList = new $.Deferred();

        Interlock.Crypto.cipherList();
        Interlock.Crypto.keyList();

        /* waits until cipher and key lists have been filled with the backend data */
        $.when(Interlock.cipherList, Interlock.keyList).done(function () {
          $.each(Interlock.Crypto.getCiphers(), function(index, cipher) {
            $availableCiphers.push($(document.createElement('option')).attr('value', cipher.name)
                                                                      .text(cipher.name));
          });

          $.each(Interlock.Crypto.getPrivateKeys(), function(index, key) {
            $availableKeys.push($(document.createElement('option')).attr('value', key.path)
                                                                   .text(key.identifier));
          });

          $selectCiphers.append($availableCiphers);
          $selectKeys.append($availableKeys);

          $selectCiphers.change(function() {
            var selectedCipher = $('#cipher > option:selected').val();

            switch (selectedCipher) {
              case 'AES-256-OFB':
                $('#password').attr('placeholder', 'decryption password');

                $('#key').hide();
                $('#password').show();

                break;
              case 'OpenPGP':
                $('#password').attr('placeholder', 'key password');

                $('#key').show();
                $('#password').show();

                break;
              default:
                $('#password').value = '';
                $('#key').value = '';

                $('#password').hide();
                $('#key').hide();
            }
          });

          var buttons = { 'Decrypt': function() {
              Interlock.FileManager.fileDecrypt( path, {cipher: $('#cipher').val(),
              password: $('#password').val(), key: $('#key').val() })
            }
          };

          var elements = [$selectCiphers,
                          $selectKeys,
                          $(document.createElement('input')).attr('id', 'password')
                                                            .attr('name', 'password')
                                                            .attr('value', '')
                                                            .attr('type', 'password')
                                                            .attr('placeholder', 'decryption password')
                                                            .addClass('text ui-widget-content ui-corner-all')];

          Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
            submitButton: 'Decrypt', title: 'Decrypt File' });

          Interlock.UI.modalFormDialog('open');

          $('#password').hide();
          $('#key').hide();

          /* pre-select the cipher based on the file extension */
          $.each(Interlock.Crypto.getCiphers(), function(index, cipher) {
            if (path.split('.').pop() === cipher.ext) {
              $('#cipher').val(cipher.name).change();
            }
          });
        });
      }));

      /* file sign */
      menuEntries.push($(document.createElement('li')).text('Sign')
                                                      .click(function() {

        var $selectSignKeys = $(document.createElement('select')).attr('id', 'sig_key')
                                                                 .attr('name', 'sig_key');

        var $availableSignKeys = [$(document.createElement('option')).attr('value', '')
                                                                     .text('choose signing key')];
        Interlock.keyList = new $.Deferred();
        Interlock.cipherList = new $.Deferred();

        Interlock.Crypto.cipherList();
        Interlock.Crypto.keyList();

        /* waits until cipher and key lists have been filled with the backend data */
        $.when(Interlock.cipherList, Interlock.keyList).done(function () {
          $.each(Interlock.Crypto.getSignKeys(), function(index, key) {
            $availableSignKeys.push($(document.createElement('option')).attr('value', key.path)
                                                                       .text(key.identifier));
          });

          $selectSignKeys.append($availableSignKeys);

          var buttons = { 'Sign': function() {
            Interlock.FileManager.fileSign({cipher: Interlock.Crypto.getKeyCipher($('#sig_key option:selected').text()),
                                            password: $('#password').val(),
                                            key: $('#sig_key').val(), src: path});
            }
          };

          var elements = [$selectSignKeys,
                          $(document.createElement('input')).attr('id', 'password')
                                                            .attr('name', 'password')
                                                            .attr('value', '')
                                                            .attr('type', 'password')
                                                            .attr('placeholder', 'key password')
                                                            .addClass('text ui-widget-content ui-corner-all')];
 
          Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
            submitButton: 'Sign', title: 'Sign File'});
          Interlock.UI.modalFormDialog('open');
        });
      }));

      /* file verify */
      menuEntries.push($(document.createElement('li')).text('Verify')
                                                      .click(function() {

        var $selectVerifyKeys = $(document.createElement('select')).attr('id', 'verify_key')
                                                                   .attr('name', 'verify_key');

        var $availableVerifyKeys = [$(document.createElement('option')).attr('value', '')
                                                                       .text('choose a signature verification key')];
        Interlock.keyList = new $.Deferred();
        Interlock.cipherList = new $.Deferred();

        Interlock.Crypto.cipherList();
        Interlock.Crypto.keyList();

        /* waits until cipher and key lists have been filled with the backend data */
        $.when(Interlock.cipherList, Interlock.keyList).done(function () {
          $.each(Interlock.Crypto.getVerifyKeys(), function(index, key) {
            $availableVerifyKeys.push($(document.createElement('option')).attr('value', key.path)
                                                                         .text(key.identifier));
          });

          $selectVerifyKeys.append($availableVerifyKeys);

          var buttons = { 'Verify': function() {
              Interlock.FileManager.fileVerify({src: $('#src').val(), sig_path: $('#sig_path').val(),
                                                key: $('#verify_key').val(),
                                                cipher: Interlock.Crypto.getKeyCipher($('#verify_key option:selected').text()) });
            }
          };

          var elements = [$(document.createElement('input')).attr('id', 'src')
                                                            .attr('name', 'src')
                                                            .attr('value', path)
                                                            .attr('type', 'text')
                                                            .attr('placeholder', 'file to verify')
                                                            .addClass('text ui-widget-content ui-corner-all'),
                          $selectVerifyKeys,
                          $(document.createElement('input')).attr('id', 'sig_path')
                                                            .attr('name', 'sig_path')
                                                            .attr('value', '')
                                                            .attr('type', 'text')
                                                            .attr('placeholder', 'signature file')
                                                            .addClass('text ui-widget-content ui-corner-all')];

          Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
            submitButton: 'Verify', title: 'Verify File Signature'});
          Interlock.UI.modalFormDialog('open');
        });
      }));

      /* add 'Key Info' menu - except for password. Reduntant check password
         keys cannot be uploaded in first place.
         Download function is disabled for all the key files. */
      if (inode.key) {
        if (inode.key.key_format !== 'password') {
          menuEntries.push($(document.createElement('li')).text('Key Info')
                                                          .click(function() {
                                                            Interlock.Crypto.keyInfo(inode.key.path);
                                                          }));
        }
      }

      if (inode.private) {
        menuEntries.push($(document.createElement('li')).text('Extract')
                                                        .addClass('disabled'));
        menuEntries.push($(document.createElement('li')).text('Compress')
                                                        .addClass('disabled'));
        menuEntries.push($(document.createElement('li')).text('View')
                                                        .addClass('disabled'));
        menuEntries.push($(document.createElement('li')).text('Download')
                                                        .addClass('disabled'));
      } else {
        /* add the extract action for the supported archive files */
        if ($.inArray((inode.name.split('.').pop() || ''),
            SUPPORTED_ARCHIVE_EXTENSIONS) >= 0) {
          menuEntries.push($(document.createElement('li')).text('Extract')
                                                        .click(function() {
            var buttons = { 'Extract': function() { Interlock.FileManager.fileExtract({ src: path, dst: $('#dst').val() }) } };

            var elements = [$(document.createElement('p')).text('Destination directory (absolute path):')
                                                          .addClass('text ui-widget-content ui-corner-all'),
                            $(document.createElement('input')).attr('id', 'dst')
                                                              .attr('name', 'dst')
                                                              .attr('value', (path.split('.')[0] || sessionStorage.mainViewPwd))
                                                              .attr('type', 'text')
                                                              .attr('placeholder', 'destination directory')
                                                              .addClass('text ui-widget-content ui-corner-all')];
            Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
              submitButton: 'Extract', title: 'Extract' });
            Interlock.UI.modalFormDialog('open');
                                                          }));
        }

        /* add the compress action for files */
        menuEntries.push($(document.createElement('li')).text('Compress')
                                                        .click(function() {
          var buttons = { 'Compress': function() { Interlock.FileManager.fileCompress({ src: path, dst: $('#dst').val() }) } };

          var elements = [$(document.createElement('p')).text('Destination archive (absolute path):')
                                                        .addClass('text ui-widget-content ui-corner-all'),
                          $(document.createElement('input')).attr('id', 'dst')
                                                            .attr('name', 'dst')
                                                            .attr('value', path + '.zip')
                                                            .attr('type', 'text')
                                                            .attr('placeholder', 'destination archive')
                                                            .addClass('text ui-widget-content ui-corner-all')];
          Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
            submitButton: 'Compress', title: 'Compress' });
          Interlock.UI.modalFormDialog('open');
        }));

        if (inode.size <= MAX_VIEW_SIZE) {
          menuEntries.push($(document.createElement('li')).text('View')
                                                          .click(function() {
                                                            Interlock.FileManager.fileDownloadView(path);
                                                          }));
        } else {
          menuEntries.push($(document.createElement('li')).text('View')
                                                          .addClass('disabled'));
        }

        menuEntries.push($(document.createElement('li')).text('Download')
                                                        .click(function() {
                                                          Interlock.FileManager.fileDownload(path);
                                                        }));
      }
    }

    contextMenu.append(menuEntries);
  }

  this.entityDragHover = function(e) {
    e.stopPropagation();
    e.preventDefault();

    if (e.type === 'dragover') {
      $('.entitydrag').addClass('hover');
    } else {
      $('.entitydrag').removeClass('hover');
    }
  };

  this.selectButtonHandler = function(e) {
    var files = e.target.files;

    for (var i = 0, f; f = files[i]; i++) {
      Interlock.FileManager.uploadFile(f);
    }
  };

  this.entitySelectHandler = function(e) {
    Interlock.FileManager.entityDragHover(e);

    /* Chrome uses e.dataTransfer.items
       Firefox uses e.dataTransfer.files */
    var items = e.dataTransfer.items || e.dataTransfer.files;

    for (var i = 0; i < items.length; i++) {
      var entry = items[i];

      if (entry.getAsEntry) {
        /* Standard HTML5 API */
        entry = entry.getAsEntry();
      } else if (entry.webkitGetAsEntry) {
        /* WebKit HTML5 API */
        entry = entry.webkitGetAsEntry();
      } else {
        /* Firefox, IE */
      }

      if (entry.isFile) {
        entry.file(Interlock.FileManager.uploadFile);
      } else if (entry.isDirectory) {
        Interlock.FileManager.processDirectory(entry);
      } else {
        /* Firefox does not have a clean way to check if the entry
           is a directory */
        if (entry.type === '') {
          var reader = new FileReader();

          reader.onload = function (e) {
            /* entry is a file */
            Interlock.FileManager.uploadFile(entry);
          };
          reader.onerror = function (e) {
            /* entry is a directory */
            Interlock.Session.createEvent({'kind': 'critical',
              'msg': '[Interlock.FileManager] your browser does not support directory drag and drop'});
          };

          reader.readAsBinaryString(entry);
        } else {
         Interlock.FileManager.uploadFile(entry);
        }
      }
    }
  };

  this.processDirectory = function(directory, path) {
    var path = path || '';
    var dirReader = directory.createReader();

    dirReader.readEntries( function(entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isFile) {
          entries[i].file(function(file) {
            Interlock.FileManager.uploadFile(file, path + directory.name + '/');
          });
        } else {
          Interlock.FileManager.processDirectory(entries[i], path + directory.name + "/");
        }
      }
    });
  };

  this.uploadFile = function(file, path) {
    /* prevent collisions in the notifications area when the same file is
       uploaded multiple times in the same session */
    var rnd = Math.floor((Math.random() * 1000000) + 1);
    var path = path || '';
    var xhr = new XMLHttpRequest();
    var $progressBar = $(document.createElement('li')).text(file.name)
                                                      .addClass('progress')
                                                      .attr('id', file.name + '_' + rnd)
                                                      .prependTo($('#uploads'));
    var fileName = file.name;

    /* directory upload, applies only to Chrome */
    if (file.webkitRelativePath && file.name !== file.webkitRelativePath) {
      fileName = file.webkitRelativePath;
    }

    xhr.upload.addEventListener('progress', function(e) {
      var pc = parseInt(e.loaded / e.total * 100);
      /* use document.getElementById(), jQuery selectors cannot be used here */
      document.getElementById(file.name + '_' + rnd).style.backgroundPosition = pc + '% 0';
      document.getElementById(file.name + '_' + rnd).innerText = file.name + ' ' + pc + '%';
    });

    xhr.onreadystatechange = function(e) {
      /* FIXME: add a redirect to login in case of 401 Unauthorized or similar */
      if (xhr.readyState === 4) {
        /* use document.getElementById(), jQuery selectors cannot be used here */
        if (xhr.status === 200) {
          document.getElementById(file.name + '_' + rnd).className = 'success';
        } else {
          document.getElementById(file.name + '_' + rnd).className = 'failure';
          document.getElementById(file.name + '_' + rnd).innerText = file.name + ' - FAILED';
        }

        /* FIXME: optimization, don't perform a fileList for every file */
        Interlock.FileManager.fileList('mainView');
      }
    };

    xhr.open('POST', document.getElementById('upload_form').action, true);

    xhr.setRequestHeader('X-XSRFToken', sessionStorage.XSRFToken);
    xhr.setRequestHeader('X-UploadFilename',
      sessionStorage.mainViewPwd + (sessionStorage.mainViewPwd.slice(-1) === '/' ? '' : '/') + path + fileName);
    xhr.setRequestHeader('X-ForceOverwrite', 'true');

    xhr.send(file);
  };
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the file listed in the view according with
 * the results returned by the backend
 *
 * @param {Object} backendData
 * @param {Object} commandArguments view, pwd, sort
 * @returns {}
 */
Interlock.FileManager.fileListCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      /* updates view pwd and sorting rules */
      sessionStorage[args.view + 'Pwd'] = args.pwd;
      sessionStorage[args.view + 'SortAttribute'] = args.sort.attribute;
      sessionStorage[args.view + 'SortAsc'] = args.sort.asc;

      Interlock.FileManager.refreshView(args.view, backendData.response.inodes);
      Interlock.FileManager.refreshDiskUsage(backendData.response.total_space, backendData.response.free_space);
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
                                     'msg': '[Interlock.FileManager.fileListCallback] ' + backendData.response});

      /* refresh the view with the root directory content on non-valid pwds */
      $.each(backendData.response, function(index, error) {
        if (error.match(/no such file or directory/)) {
          Interlock.FileManager.fileList(args.view, '/');

          return false;
        }
      });
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg': '[Interlock.Session.fileListCallback] ' + e});
  } finally {
    $('#upload_form > fieldset > .ajax_overlay').remove();
  }
}

/**
 * @function
 * @public
 *
 * @description
 * Refresh the file/directory list in the view according with
 * the results returned by the backend
 *
 * @param {string} view FileManager view attached to this request
 * @param {string} pwd
 * @param {Object} [sort = { attribute: 'name', asc: true }]
 * @returns {}
 */
Interlock.FileManager.fileList = function(view, pwd, sort) {
  try {
    var pwd = pwd || sessionStorage[view + 'Pwd'];
    var sort = sort || { attribute: sessionStorage[view + 'SortAttribute'],
                         asc: sessionStorage[view + 'SortAsc'] };

    Interlock.UI.ajaxLoader('#upload_form > fieldset');

    Interlock.Backend.APIRequest(Interlock.Backend.API.file.list, 'POST',
      JSON.stringify({path: pwd}), 'FileManager.fileListCallback',
      null, {view: view, pwd: pwd, sort: sort});
  } catch (e) {
    $('#upload_form > fieldset > .ajax_overlay').remove();
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileList] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, perform the final 'GET' to the file url returned by
 * the backend
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileDownloadCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
    /* Creates a virtual link using the following urls format:
       /api/file/download?id=9zOCouyy4SR2ARXOl3Dkpg== */
      var link = document.createElement('a');
      link.href = Interlock.Backend.API.prefix + Interlock.Backend.API.file.download + '?id=' + backendData.response;
      link.style.display = 'none';

      if (link.download !== undefined) {
      /* Set HTML5 download attribute:
         this will prevent the browser from open the file (if supported).

         The value of the download attribute is only a placeholder, the
         filename is overwritten by the Content-Disposition Header passed
         by the backend */
        link.download = 'download';
      }

      /* On IE the link must be appended in the page otherwise the click
         event is not properly dispatched */
      document.body.appendChild(link);

      /* Dispatch the click event to the virtual link */
      if (document.createEvent) {
        var e = document.createEvent('MouseEvents');
        e.initEvent('click', true, true);
        link.dispatchEvent(e);

        return true;
      }
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileDownloadCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Session.fileDownloadCallback] ' + e});
  } finally {
    /* Ensure a proper clean-up of the download link */
    if (link && link.parentNode === document.body) {
      document.body.removeChild(link);
    }
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Download a file or a directory archive
 *
 * @param {string} path fullpath of the file/directory to download
 * @returns {}
 */
Interlock.FileManager.fileDownload = function(path) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.download, 'POST',
      JSON.stringify({path: path}), 'FileManager.fileDownloadCallback');
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
 * Callback function, download and display the file content in text inside a dialog
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileDownloadViewCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      /* uses browser downloader, urls format:
       * /api/file/download?id=9zOCouyy4SR2ARXOl3Dkpg== */
      $.get(Interlock.Backend.API.prefix + Interlock.Backend.API.file.download, {id: backendData.response})
        .done(function(data) {
          var buttons = {'Close': function() { Interlock.UI.modalFormDialog('close'); } };
          var elements = [$(document.createElement('p')).append($(document.createElement('pre')).text(data)
                                                                                                .attr('id', 'data')
                                                                                                .attr('spellcheck',false)
                                                                                                .addClass('file_contents'))];

          Interlock.UI.modalFormConfigure({elements: elements, buttons: buttons,
                                           noCancelButton: true, submitButton: 'Close',
                                           title: 'File Contents', height: 600, width: 800});

          Interlock.UI.modalFormDialog('open');
        })
        .fail(function() {
          Interlock.Session.createEvent({'kind': 'critical',
            'msg': '[Interlock.FileManager.getDownloadViewCallback] file download failed'});
        });
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileDownloadViewCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Session.fileDownloadViewCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Download a file and display its content in text inside a dialog
 *
 * @param {Object} path of the file
 * @returns {}
 */
Interlock.FileManager.fileDownloadView = function(path) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.download, 'POST',
      JSON.stringify({path: path}), 'FileManager.fileDownloadViewCallback');
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
 * Callback function, refresh the file listed in the mainView according with
 * the current pwd after file deletions
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileDeleteCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileDeleteCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Session.fileDeleteCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Delete one or more files/directories
 *
 * @param [{string}] path fullpath of the file/directory to delete
 * @returns {}
 */
Interlock.FileManager.fileDelete = function(path) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.delete, 'POST',
      JSON.stringify({path: path}), 'FileManager.fileDeleteCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileDelete] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the file listed in the mainView according with
 * the current pwd after directory creation
 *
 * @param {Object} commandArguments
 * @returns {}
 */
Interlock.FileManager.mkdirCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.mkdirCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical', 'msg':
      '[Interlock.FileManager.mkdirCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Creates a new directory under the current mainView pwd
 *
 * @param [{string}] path fullpath of the directory to create
 * @returns {}
 */
Interlock.FileManager.mkdir = function(path) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.mkdir, 'POST',
      JSON.stringify({path: sessionStorage['mainViewPwd'] +
        (sessionStorage['mainViewPwd'].slice(-1) === '/' ? '' : '/') + path}),
      'FileManager.mkdirCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.mkdir] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the file listed in the mainView according with
 * the current pwd after file/directory has been copied
 *
 * @param {Object} commandArguments
 * @returns {}
 */
Interlock.FileManager.fileCopyCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileCopy] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileCopy] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Copy a file or directory
 *
 * @param {Object} copy options: source and destination paths
 * @returns {}
 */
Interlock.FileManager.fileCopy = function(args){
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.copy, 'POST',
      JSON.stringify({src: args.src, dst: args.dst}),
      'FileManager.fileCopyCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileCopy] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the file listed in the mainView according with
 * the current pwd after file/directory has been moved
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileMoveCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.MoveCopy] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileMove] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Move a file or directory
 *
 * @param {Object} commandArgs, move options: src, dst
 * @returns {}
 */
Interlock.FileManager.fileMove = function(args){
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.move, 'POST',
      JSON.stringify({src: args.src, dst: args.dst}),
      'FileManager.fileMoveCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileMove] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the file listed in the mainView according with
 * the current pwd after encryption is submitted
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileEncryptCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileEncrypt] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileEncrypt] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Encrypt one or more files
 *
 * @param {string} path fullpath of the file to encrypt
 * @param {Object} commandArguments key, password, wipe_src, sign, sig_ley
 * @returns {}
 */
Interlock.FileManager.fileEncrypt = function(path, args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.encrypt, 'POST',
      JSON.stringify({src: path, cipher: args.cipher, password: args.password,
        key: (args.key === undefined ? '' : args.key),
        wipe_src: (args.wipe_src === undefined ? false : args.wipe_src),
        sign: (args.sign === undefined ? false : args.sign),
        sig_key: (args.sig_key === undefined ? '' : args.sig_key) }),
      'FileManager.fileEncryptCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileEncrypt] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, refresh the file listed in the mainView according with
 * the current pwd after decryption is submitted
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileDecryptCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
                                     'msg': '[Interlock.FileManager.fileDecrypt] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileDecrypt] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Decrypt one or more files
 *
 * @param {string} path fullpath of the file to decrypt
 * @param {Object} decryption options: src, password, verify, key, sig_key
 * @returns {}
 */
Interlock.FileManager.fileDecrypt = function(path, args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.decrypt, 'POST',
      JSON.stringify({src: path,
        password: args.password,
        verify: false,
        key: (args.key === undefined ? '' : args.key),
        sig_key: (args.sig_key === undefined ? '' : args.sig_key),
        cipher: args.cipher }),
      'FileManager.fileDecryptCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileDencrypt] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function file sign
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileSignCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList('mainView');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileSignCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileSignCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Sign one file
 *
 * @param {Object} commandArguments src, cipher, password, key
 * @returns {}
 */
Interlock.FileManager.fileSign = function(args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.sign, 'POST',
      JSON.stringify({src: args.src, cipher: args.cipher, password: args.password,
        key: (args.key === undefined ? '' : args.key)}), 'FileManager.fileSignCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileSign] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function file verify
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileVerifyCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileVerifyCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileVerifyCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Verify one file
 *
 * @param {Object} commandArguments src, sig, key, cipher
 * @returns {}
 */
Interlock.FileManager.fileVerify = function(args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.verify, 'POST',
      JSON.stringify({src: args.src, sig: args.sig_path, key: args.key, cipher: args.cipher}),
        'FileManager.fileVerifyCallback');
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileVerify] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, fileExtract callback
 *
 * @param {Object} commandArguments: destination directory
 * @returns {}
 */
Interlock.FileManager.fileExtractCallback = function(backendData, dst) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');

      if (sessionStorage.mainViewPwd === dst) {
        Interlock.FileManager.fileList('mainView');
      }
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileExtractCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileExtractCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Extract an archive file
 *
 * @param {Object} extract options: archive path and destination directory
 * @returns {}
 */
Interlock.FileManager.fileExtract = function(args){
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.extract, 'POST',
      JSON.stringify({src: args.src, dst: args.dst}),
      'FileManager.fileExtractCallback', null, args.dst);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileExtract] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Callback function, fileCompress callback
 *
 * @param {Object} commandArguments: destination directory
 * @returns {}
 */
Interlock.FileManager.fileCompressCallback = function(backendData, dst) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');

      if (sessionStorage.mainViewPwd === dst) {
        Interlock.FileManager.fileList('mainView');
      }
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileCompressCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileCompressCallback] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Compress a file or directory
 *
 * @param {Object} compress options: source path and destination archive
 * @returns {}
 */
Interlock.FileManager.fileCompress = function(args){
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.compress, 'POST',
      JSON.stringify({src: args.src, dst: args.dst}),
      'FileManager.fileCompressCallback', null, args.dst);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileCompress] ' + e});
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Sort inodes following the current sorting method configured by the user
 * for the current tab
 *
 * @param {array} unordered inodes array
 * @returns {array} ordered inodes array
 */
Interlock.FileManager.sortInodes = function(inodes) {
  try {
    var directories = [];
    var files = [];
    var directoriesKeys = [];
    var filesKeys = [];

    var sortedDirectories = [];
    var sortedFiles = [];

    var sortAttr = 'name';

    /* FIXME: optimize sorting algorithm */
    if (sessionStorage.mainViewSortAttribute !== 'name' ||
        sessionStorage.mainViewSortAttribute !== 'size' ||
        sessionStorage.mainViewSortAttribute !== 'mtime') {
      sessionStorage.mainViewSortAttribute = 'name';
    }

    sortAttr = sessionStorage.mainViewSortAttribute;

    $.each(inodes, function(index, inode) {
      if (inode.dir) {
        directories.push(inode);
        directoriesKeys.push(inode[sortAttr]);
      } else {
        files.push(inode);
        filesKeys.push(inode[sortAttr]);
      }
    });

    directoriesKeys = directoriesKeys.sort();
    filesKeys = filesKeys.sort();

    $.each(directoriesKeys, function(dirKeyIndex, dirKey) {
      $.grep(directories, function(e) {
        if (e[sortAttr] === dirKey) {
          sortedDirectories.push(e);
        }
      });
    });

    $.each(filesKeys, function(fileKeyIndex, fileKey) {
      $.grep(files, function(e) {
        if (e[sortAttr] === fileKey) {
          sortedFiles.push(e);
        }
      });
    });

    return $.merge(sortedDirectories, sortedFiles);
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.sortInodes] unable to sort file list' + e});
  }
};

/* FIXME: add Inode class, and move all the inode methods here Interlock.Inode = function() { };
 * FIXME: cleanup from code repetition: all the file functions (fileCopy/Move/Delete/etc) 
          are using very similar code snippets */
