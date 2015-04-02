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

  /* set default pwd and sorting rule for the main file manager
     and the browsing view */
  sessionStorage.mainViewPwd = sessionStorage.mainViewPwd || '/';
  sessionStorage.mainViewSortAttribute = sessionStorage.mainViewSortAttribute || 'name';
  sessionStorage.mainViewSortAsc = sessionStorage.mainViewSortAsc || true;

  sessionStorage.browsingViewPwd = '/';
  sessionStorage.browsingViewSortAttribute = 'name';
  sessionStorage.browsingViewSortAsc = true;

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
      var buttons = { 'Add directory': function() { Interlock.FileManager.mkdir($('#directory').val());} };
      var elements = [$(document.createElement('input')).attr('id', 'directory')
                                                        .attr('name', 'directory')
                                                        .attr('placeholder', 'directory name')
                                                        .attr('type', 'text')
                                                        .addClass('text ui-widget-content ui-corner-all')];

      Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
        submitButton: 'Add directory', title: 'Create new directory' });
      Interlock.UI.modalFormDialog('open');
    });

    /* register the on 'click' event to the new key button */
    $('#upload_key').on('click', function() {
      var $selectCiphers = $(document.createElement('select')).attr('id', 'cipher')
                                                              .attr('name', 'cipher');

      var $availableCiphers = [$(document.createElement('option')).attr('value', '')
                                                                  .text('choose encryption cipher')];

      var buttons = { 'Add key': function() {
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
                                                           .attr('placeholder', 'PGP key - armor format')
                                                           .addClass('text ui-widget-content ui-corner-all key'),
                      $(document.createElement('input')).attr('id', 'private')
                                                        .attr('name', 'private')
                                                        .attr('placeholder', 'private')
                                                        .attr('type', 'checkbox')
                                                        .addClass('text ui-widget-content ui-corner-all'),
                      $(document.createElement('label')).text('private (leave it blank for public key)')
                                                        .attr('for', 'private'),
                      $(document.createElement('input')).attr('id', 'key_format')
                                                        .attr('name', 'key_format')
                                                        .attr('placeholder', 'key format')
                                                        .attr('type', 'text')
                                                        .attr('value', 'armor')
                                                        .addClass('text ui-widget-content ui-corner-all')
                                                        .hide()];

      Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
        submitButton: 'Upload key', title: 'Upload a new key', height: 600, width: 550 });
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
        traversingPath += directory + '/';
        var $pwdNested = $(document.createElement('span'));
        var path = traversingPath;

        $pwd.append('&nbsp; &#9656; &nbsp;');
        $pwdNested.text(directory)
                  .appendTo($pwd)
                  .click(function() {
                    Interlock.FileManager.fileList(view, path);
                  });
      }
    });

    /* refresh file/directory table */
    $.each(inodes, function(index, inode) {
      /* don't show files in the browsingView */
      if (view === 'browsingView' && inode.dir !== true) {
        /* equivalent to continue inside a jQuery .each() loop */
        return;
      }

      var size = inode.size || '-';
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
    if (inode.key || inode.key_path) {
      menuEntries.push($(document.createElement('li')).text('Copy to')
                                                      .addClass('disabled'));

      menuEntries.push($(document.createElement('li')).text('Move to')
                                                      .addClass('disabled'));
    } else {
      menuEntries.push($(document.createElement('li')).text('Copy to')
                                                      .click(function() {
        var buttons = { 'Copy to': function() { Interlock.FileManager.fileCopy({ src: path, dst: $('#dst').val() }) } };

        var elements = [$(document.createElement('input')).attr('id', 'dst')
                                                          .attr('name', 'dst')
                                                          .attr('value', path + '.copy')
                                                          .attr('type', 'text')
                                                          .attr('placeholder', 'destination')
                                                          .addClass('text ui-widget-content ui-corner-all')];

        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          submitButton: 'Copy to', title: 'Copy to' });
        Interlock.UI.modalFormDialog('open');
      }));

      menuEntries.push($(document.createElement('li')).text('Move to')
                                                      .click(function() {
        var buttons = { 'Move to': function() { Interlock.FileManager.fileMove({ src: path, dst: $('#dst').val() }) } };

        var elements = [$(document.createElement('input')).attr('id', 'dst')
                                                          .attr('name', 'dst')
                                                          .attr('value', path + '.moved')
                                                          .attr('type', 'text')
                                                          .attr('placeholder', 'destination')
                                                          .addClass('text ui-widget-content ui-corner-all')];

        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          submitButton: 'Move to', title: 'Move to' });
        Interlock.UI.modalFormDialog('open');
      }));
    }

    menuEntries.push($(document.createElement('li')).text('Delete')
                                                    .click(function() {
                                                      Interlock.FileManager.fileDelete([path]);
                                                    }));
    if (inode.dir) {
      if (inode.key_path) {
        menuEntries.push($(document.createElement('li')).text('Download (zip archive)')
                                                        .addClass('disabled'));
      } else {
        menuEntries.push($(document.createElement('li')).text('Download (zip archive)')
                                                      .click(function() {
                                                        Interlock.FileManager.fileDownload(path);
                                                      }));
      }
    } else {
      if (inode.key && inode.key !== 'password') {
        menuEntries.push($(document.createElement('li')).text('Encrypt')
                                                        .addClass('disabled'));
        menuEntries.push($(document.createElement('li')).text('Decrypt')
                                                        .addClass('disabled'));
      } else {
        menuEntries.push($(document.createElement('li')).text('Encrypt')
                                                        .click(function() {
          var $selectCiphers = $(document.createElement('select')).attr('id', 'cipher')
                                                                  .attr('name', 'cipher');

          var $selectKeys = $(document.createElement('select')).attr('id', 'key')
                                                               .attr('name', 'key');

          var $availableCiphers = [$(document.createElement('option')).attr('value', '')
                                                                      .text('choose encryption cipher')];

          var $availableKeys = [$(document.createElement('option')).attr('value', '')
                                                                   .text('choose encryption key')];

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

            $selectCiphers.append($availableCiphers);
            $selectKeys.append($availableKeys);

            $selectCiphers.change(function() {
              var selectedCipher = $('#cipher > option:selected').val();

              switch (selectedCipher) {
                case 'AES-256-OFB':
                  $('#password').attr('placeholder', 'encryption password');

                  $('#key').hide();
                  $('#password').show();

                  break;
                case 'OpenPGP':
                  $('#password').value = '';

                  $('#key').show();
                  $('#password').hide();

                  break;
                default:
                  $('#password').value = '';
                  $('#key').value = '';

                  $('#password').hide();
                  $('#key').hide();
              }
            });

            var buttons = { 'Encrypt': function() {
              Interlock.FileManager.fileEncrypt( path,
                  {cipher: $('#cipher').val(), password: $('#password').val(), key: $('#key').val() })
              }
            };

            var elements = [$selectCiphers,
                            $selectKeys,
                            $(document.createElement('input')).attr('id', 'password')
                                                              .attr('name', 'password')
                                                              .attr('value', '')
                                                              .attr('type', 'password')
                                                              .attr('placeholder', 'encryption password')
                                                              .addClass('text ui-widget-content ui-corner-all')];

            Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
              submitButton: 'Encrypt', title: 'Encrypt File' });

            Interlock.UI.modalFormDialog('open');

            $('#password').hide();
            $('#key').hide();
          });
        }));

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
                  $('#password').attr('placeholder', 'GPG key password');

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
      }

      menuEntries.push($(document.createElement('li')).text('Verify')
                                                      .addClass('disabled'));

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
        menuEntries.push($(document.createElement('li')).text('Download')
                                                        .addClass('disabled'));
      } else {
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
      /* uses browser downloader, urls format:
       * /api/file/download?id=9zOCouyy4SR2ARXOl3Dkpg== */
      window.open(Interlock.Backend.API.prefix +
        Interlock.Backend.API.file.download + '?id=' + backendData.response);
    } else {
      Interlock.Session.createEvent({'kind': backendData.status,
        'msg': '[Interlock.FileManager.fileDownloadCallback] ' + backendData.response});
    }
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.Session.fileDownloadCallback] ' + e});
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
 * Callback function, refresh the file listed in the mainView according with
 * the current pwd after file deletions
 *
 * @param {Object} backendData
 * @returns {}
 */
Interlock.FileManager.fileDeleteCallback = function(backendData) {
  try {
    if (backendData.status === 'OK') {
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
 * @param {Object} commandArguments key, wipe_src, sign, sig_ley
 * @returns {}
 */
Interlock.FileManager.fileEncrypt = function(path, args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.encrypt, 'POST',
      JSON.stringify({src: path, cipher: args.cipher, password: args.password,
        key: (args.key === undefined ? '' : args.key),
        wipe_src: (args.wipe_src === undefined ? false : args.wipe_src),
        sign: false,
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

/* FIXME: add Inode class, and move all the inode methods here Interlock.Inode = function() { };
 * FIXME: cleanup from code repetition: all the file functions (fileCopy/Move/Delete/etc) 
          are using very similar code snippets */
