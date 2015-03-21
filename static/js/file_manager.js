/**
 * @class
 * @constructor
 *
 * @description
 * FileManager instance class
 */
Interlock.FileManager = new function() {
  /** @private */
  var DEFAULT_PWD = '/';
  var DEFAULT_SORT =  { attr: 'name', asc: true };
  var view = { };

  /** @protected */
  this.createView = function(name, pwd, sort) {
    var newView = { name: name,
                    pwd: (pwd ? pwd : DEFAULT_PWD),
                    sort: (sort ? sort : DEFAULT_SORT),
                    inodes: [] };

    /* FileManager initialization */
    var $fileSelect = $('#fileselect');
    var $directorySelect = $('#directoryselect');
    var $entityDrag = $('.entitydrag');
    var $submitButton = $('#submitbutton');
    var xhr = new XMLHttpRequest();

    if (view.hasOwnProperty(name)) {
      Interlock.Session.createEvent({'kind': 'info',
        'msg': '[Interlock.FileManager.createView] failed to create view "' + name + '", view already exists'});
    } else {
      view[name] = newView;

      Interlock.Session.createEvent({'kind': 'info',
        'msg': '[Interlock.FileManager.createView] new view "' + name + '" has been created'});
    }

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

    /* remove the context menu on any left click on the page */
    $(document).on('click', function(e) {
      $('ul.inode_menu').remove();
    });

    /* fill the new File Manager view with the inode list */
    Interlock.FileManager.fileList(newView.name, newView.pwd, newView.sort);
  };

  this.destroyView = function(name) {
    if (view.hasOwnProperty(name)) {
      delete view[name];
      Interlock.Session.createEvent({'kind': 'info',
        'msg': '[Interlock.FileManager.destroyView] view "' + name + '" has been destroyed'});
    } else {
      Interlock.Session.createEvent({'kind': 'info',
        'msg': '[Interlock.FileManager.destroyView] failed to destroy view "' + name + '", view does not exists'});
    }
  };

  this.refreshView = function(args, backendData) {
    if (view[args.view]) {
      /* udates the view internal structure:
         list of inodes, current pwd and applied sort logic */
      view[args.view].inodes = backendData.inodes;
      view[args.view].pwd = (args.pwd ? args.pwd : view[args.view].pwd);
      view[args.view].sort = (args.sort ? args.sort : view[args.view].sort);

      var currentView = view[args.view];
      var traversingPath = '/';
      var $inodesSelector = $('#file_manager_' + currentView.name + ' > div.inodes_table_container > table > tbody.inodes_container');
      var $pwdSelector = $('#file_manager_' + currentView.name + ' > span.pwd');
      var $pwdRoot = $(document.createElement('span'));
      var $diskUsageSelector = $('#disk_usage');
      var freeSpace = 0;
      var totalSpace = 0;

      /* updates the disk usage info */
      if (backendData.free_space !== undefined && backendData.total_space !== undefined) {
        freeSpace = parseFloat(backendData.free_space / (1000 * 1000 * 1000)).toFixed(2);
        totalSpace = parseFloat(backendData.total_space / (1000 * 1000 * 1000)).toFixed(2);
      }

      $pwdSelector.html('');
      $inodesSelector.html('');

      $pwdRoot.html('/')
              .appendTo($pwdSelector)
              .click(function() {
                 Interlock.FileManager.fileList(currentView.name, '/');
              });

      /* updates the pwd browsing links */
      $.each(currentView.pwd.split('/'), function(index, directory) {
        if (directory) {
          traversingPath += directory + '/';
          var $pwdNested = $(document.createElement('span'));
          var path = traversingPath;

          $pwdSelector.append('&nbsp; &#9656; &nbsp;');
          $pwdNested.text(directory)
                    .appendTo($pwdSelector)
                    .click(function() {
                      Interlock.FileManager.fileList(currentView.name, path);
                    });
        }
      });

      /* register the on 'click' event to the new directory button */
      $('#add_new_directory').on('click', function() {
        var buttons = { 'Add directory': function() { Interlock.FileManager.mkdir(currentView, $('#directory').val());} };
        var elements = [$(document.createElement('input')).attr('id', 'directory')
                                                          .attr('name', 'directory')
                                                          .attr('placeholder', 'directory name')
                                                          .attr('type', 'text')
                                                          .addClass('text ui-widget-content ui-corner-all')];

        Interlock.UI.modalFormConfigure({ elements: elements, buttons: buttons,
          submitButton: 'Add directory', title: 'Create new directory' });
        Interlock.UI.modalFormDialog('open');
      });

      /* refresh file/directory list */
      $.each(backendData.inodes, function(index, inode) {
        var size = inode.size || '-';
        var mtime = (inode.mtime === undefined) ? '-' : new Date(inode.mtime * 1000);
        mtime.setMinutes(mtime.getMinutes() - mtime.getTimezoneOffset());
        var path = currentView.pwd + (currentView.pwd.slice(-1) === '/' ? '' : '/') + inode.name;

        var $inode = $(document.createElement('tr'));
        var $inodeName = $(document.createElement('td')).text(inode.name);
        var $inodeSize = $(document.createElement('td')).text(size);
        var $inodeMtime = $(document.createElement('td')).text(mtime.toISOString().replace(/T/g, '  ').slice(0,20));

        $inode.append($inodeName, $inodeSize, $inodeMtime)
              .appendTo($inodesSelector);

        if (inode.dir) {
          $inode.addClass('directory');
          $inodeName.click(function() {
                       Interlock.FileManager.fileList(currentView.name, path);
                     });
        } else {
          $inode.addClass('file');
        }

        /* open the context menu on right click on the inode */
        $inode.on('contextmenu', function(e) { Interlock.FileManager.contextMenu(e, currentView, inode.dir, path) });

        /* updates the disk usage info */
        $diskUsageSelector.text(freeSpace + ' GB Free (' + totalSpace + ' GB Total)' );
      });
    } else {
      Interlock.Session.createEvent({'kind': 'critical',
        'msg': '[Interlock.FileManager.refreshView] failed to refresh "' + args.view + '", view does not exist'});
    }
  };

  /* dinamically creates the context menu for every inode entry in the
     File Manager view */
  this.contextMenu = function(e, view, isDirectory, path) {
    e.preventDefault();
    $('ul.inode_menu').remove();

    var menuEntries = [];
    var contextMenu = $(document.createElement('ul')).addClass('inode_menu')
                                                     .appendTo('body')
                                                     .css({top: e.pageY + 'px', left: e.pageX + 'px'});

    menuEntries.push($(document.createElement('li')).text('Copy to')
                                                    .click(function() {
      var buttons = { 'Copy to': function() { Interlock.FileManager.fileCopy(view, {src: path, dst: $('#dst').val() }) } };

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
      var buttons = { 'Move to': function() { Interlock.FileManager.fileMove(view, {src: path, dst: $('#dst').val() }) } };

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

    menuEntries.push($(document.createElement('li')).text('Delete')
                                                    .click(function() {
                                                      Interlock.FileManager.fileDelete(view, [path]);
                                                    }));
    if (isDirectory) {
      menuEntries.push($(document.createElement('li')).text('Download archive')
                                                      .addClass('disabled')
                                                      .click(function() {
                                                        Interlock.FileManager.fileDownload(path);
                                                      }));
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
            Interlock.FileManager.fileEncrypt(view, path,
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
            Interlock.FileManager.fileDecrypt(view, path, {cipher: $('#cipher').val(),
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
      }));

      menuEntries.push($(document.createElement('li')).text('Verify')
                                                      .addClass('disabled'));

      menuEntries.push($(document.createElement('li')).text('Download')
                                                      .click(function() {
                                                        Interlock.FileManager.fileDownload(path);
                                                      }));
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

    /* FIXME: add support multiple views */
    var currentView = view['mainView'];
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
        document.getElementById(file.name + '_' + rnd).className = (xhr.status === 200 ? 'success' : 'failure');

        /* FIXME: optimization, don't perform a fileList for every file */
        Interlock.FileManager.fileList(currentView.name, currentView.pwd, currentView.sort);
      }
    };

    xhr.open('POST', document.getElementById('upload_form').action, true);

    xhr.setRequestHeader('X-XSRFToken', sessionStorage.XSRFToken);
    /* FIXME: support for multiple views */
    xhr.setRequestHeader('X-UploadFilename',
      view['mainView'].pwd + (view['mainView'].pwd.slice(-1) === '/' ? '' : '/') + path + fileName);
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
      Interlock.FileManager.refreshView(args, backendData.response);
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
    Interlock.UI.ajaxLoader('#upload_form > fieldset');

    Interlock.Backend.APIRequest(Interlock.Backend.API.file.list, 'POST',
      JSON.stringify({path: pwd, sort: sort}), 'FileManager.fileListCallback',
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
 * FIXME: directory download is currently not implemented
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
 * Callback function, refresh the file listed in the view according with
 * the current pwd after file deletions
 *
 * @param {Object} backendData
 * @param {Object} commandArguments view, pwd
 * @returns {}
 */
Interlock.FileManager.fileDeleteCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.FileManager.fileList(args.view.name, args.view.pwd);
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
 * @param {string} view FileManager view attached to this request
 * @param [{string}] path fullpath of the file/directory to delete
 * @returns {}
 */
Interlock.FileManager.fileDelete = function(view, path) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.delete, 'POST',
      JSON.stringify({path: path}), 'FileManager.fileDeleteCallback',
      null, {view: view, path: path});
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
 * Callback function, refresh the file listed in the view according with
 * the current pwd after directory creation
 *
 * @param {Object} backendData view
 * @param {Object} commandArguments
 * @returns {}
 */
Interlock.FileManager.mkdirCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList(args.view.name, args.view.pwd);
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
 * Creates a new directory under the current pwd
 *
 * @param {string} view FileManager view attached to this request
 * @param [{string}] path fullpath of the directory to create
 * @returns {}
 */
Interlock.FileManager.mkdir = function(view, path) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.mkdir, 'POST',
      JSON.stringify({path: view.pwd + (view.pwd.slice(-1) === '/' ? '' : '/') + path}),
      'FileManager.mkdirCallback', null, {view: view});
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
 * Callback function, refresh the file listed in the view according with
 * the current pwd after file/directory has been copied
 *
 * @param {Object} backendData view
 * @param {Object} commandArguments
 * @returns {}
 */
Interlock.FileManager.fileCopyCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList(args.view.name, args.view.pwd);
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
 * @param {string} view FileManager view attached to this request
 * @param {Object} copy options: source and destination paths
 * @returns {}
 */
Interlock.FileManager.fileCopy = function(view, args){
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.copy, 'POST',
      JSON.stringify({src: args.src, dst: args.dst }),
      'FileManager.fileCopyCallback', null, {view: view});
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
 * Callback function, refresh the file listed in the view according with
 * the current pwd after file/directory has been moved
 *
 * @param {Object} backendData
 * @param {Object} commandArguments view
 * @returns {}
 */
Interlock.FileManager.fileMoveCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList(args.view.name, args.view.pwd);
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
 * @param {string} view FileManager view attached to this request
 * @param {Object} commandArgs, move options: src, dst
 * @returns {}
 */
Interlock.FileManager.fileMove = function(view, args){
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.move, 'POST',
      JSON.stringify({src: args.src, dst: args.dst }),
      'FileManager.fileMoveCallback', null, {view: view});
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
 * Callback function, refresh the file listed in the view according with
 * the current pwd after encryption is submitted
 *
 * @param {Object} backendData
 * @param {Object} commandArguments view
 * @returns {}
 */
Interlock.FileManager.fileEncryptCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList(args.view.name, args.view.pwd);
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
 * @param {string} view FileManager view attached to this request
 * @param {string} path fullpath of the file to encrypt
 * @param {Object} commandArguments key, wipe_src, encrypt, sign, sig_ley
 * @returns {}
 */
Interlock.FileManager.fileEncrypt = function(view, path, args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.encrypt, 'POST',
      JSON.stringify({src: path, cipher: args.cipher, password: args.password,
        key: (args.key === undefined ? '' : args.key),
        wipe_src: (args.wipe_src === undefined ? false : args.wipe_src),
        encrypt: true,
        sign: false,
        sig_key: (args.sig_key === undefined ? '' : args.sig_key) }),
      'FileManager.fileEncryptCallback', null, {view: view});
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
 * Callback function, refresh the file listed in the view according with
 * the current pwd after decryption is submitted
 *
 * @param {Object} backendData
 * @param {Object} commandArguments view
 * @returns {}
 */
Interlock.FileManager.fileDecryptCallback = function(backendData, args) {
  try {
    if (backendData.status === 'OK') {
      Interlock.UI.modalFormDialog('close');
      Interlock.FileManager.fileList(args.view.name, args.view.pwd);
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
 * @param {string} view FileManager view attached to this request
 * @param {string} path fullpath of the file to decrypt
 * @param {Object} encryption options: key, cipher, password
 * @returns {}
 */
Interlock.FileManager.fileDecrypt = function(view, path, args) {
  try {
    Interlock.Backend.APIRequest(Interlock.Backend.API.file.decrypt, 'POST',
      JSON.stringify({src: path,
        password: args.password,
        key: (args.key === undefined ? '' : args.key),
        cipher: args.cipher }),
      'FileManager.fileDecryptCallback', null, {view: view});
  } catch (e) {
    Interlock.Session.createEvent({'kind': 'critical',
      'msg': '[Interlock.FileManager.fileDencrypt] ' + e});
  }
};

/* FIXME: add Inode class, and move all the inode methods here Interlock.Inode = function() { };
 * FIXME: cleanup from code repetition: all the file functions (fileCopy/Move/Delete/etc) 
          are using very similar code snippets */
