/**
 * @class
 * @constructor
 *
 * @description
 * UI instance class
 */
Interlock.UI = new function() {
  /** @private */
  var $errorForm = $(document.createElement('div')).attr('id', 'error-form');
  var $modalForm = $(document.createElement('div')).attr('id', 'modal-form');

  $.extend($modalForm, {form: $(document.createElement('form')).appendTo($modalForm)});
  $.extend($modalForm, {fieldset: $(document.createElement('fieldset')).appendTo($modalForm.form)});

  /* appends the dialog elements to the page body */
  $('body').append($errorForm, $modalForm);

  /* initialize error form and modal form */
  errorFormInit();
  modalFormInit();

  function errorFormInit() {
    $errorForm.dialog({
      autoOpen: false,
      height: 350,
      width: 350,
      modal: true,
      buttons: { OK: function() { $errorForm.dialog('close'); } }
    });
  }

  function modalFormInit() {
    /* allow form submission with keyboard without duplicating the dialog button */
    var $input = $(document.createElement('input')).attr('type', 'submit')
                                                   .attr('tabindex', '-1')
                                                   .css({position: 'absolute', top: '-1000px'})
                                                   .appendTo($modalForm.form);
    $modalForm.dialog({
      autoOpen: false,
      height: 350,
      width: 350,
      modal: true,
      buttons: { Cancel: function() { $modalForm.dialog('close'); } }
    });
  }

  /** @protected */
  this.errorFormDialog = function(msgs) {
    $errorForm.dialog({
      autoOpen: false,
      height: 350,
      width: 350,
      modal: true,
      title: 'Interlock error',
      buttons: { OK: function() { $errorForm.dialog('close'); } },
      open: function() {
        $errorForm.html('');
        $.each(msgs, function(index, msg) {
          /* updates the error msg */
          $errorForm.append($(document.createElement('p')).text(msg));
        });
      }
    });

    $errorForm.dialog('open');
  };

  this.modalFormDialog = function(action) {
    $modalForm.dialog(action);
  };

  /* configure open function and customize form buttons for modal form */
  this.modalFormConfigure = function(options) {
    $modalForm.dialog({
      autoOpen: false,
      height: 350,
      width: 350,
      modal: true,
      title: options.title ? options.title : '',
      buttons: $.extend(options.buttons, { Cancel: function() { $modalForm.dialog('close'); } }),
      open: function() {
        /* clean up from any previous content */
        $modalForm.fieldset.html('');
        /* append to the form fieldset the custom elements specified in options */
        $.each(options.elements, function (index, element) {
          element.appendTo($modalForm.fieldset);
        });

        /* bind the enter keypress event to the configured submit button */
        if (options.submitButton !== undefined) {
          $modalForm.form.keypress(function(e) {
            var keyPressed = e.keyCode || e.which;

            if (keyPressed === 13) {
              $('button > span:contains("' + options.submitButton + '")').click();

              /* prevent event propagation */
              return false;
            }
          });
        }
      },
      close: function() {
        $modalForm.fieldset.html('');
        /* unbind the registered keypress event handler (if any) */
        $modalForm.form.unbind('keypress');
      }
    });
  };
};

/** @public */

/**
 * @function
 * @public
 *
 * @description
 * Opens a console in a new tab
 *
 * @param {Object} event, JavaScript event raised during function invockation
 * @returns {}
 */
Interlock.UI.OpenShellInABox = function(e) {
  var target = e.target;
  var port = target.getAttribute('href').match(/^:(\d+)(.*)/);

  if (port) {
    target.href = port[2];
    target.port = port[1];
  }
};

/**
 * @function
 * @public
 *
 * @description
 * Increase/decrease the font size of the page elements
 *
 * @param {Object} event, JavaScript event raised during function invockation
 * @param {Integer} resizeStep (eg. +/-1)
 * @returns {}
 */
Interlock.UI.resizeText = function(e, resizeStep) {
  var curSize = parseInt($('body').css('font-size')) + resizeStep;

  $('body').css('font-size', curSize);
  $('div').css('font-size', curSize);
  $('img').css('font-size', curSize);
  $('h1').css('font-size', curSize);
  $('button').css('font-size', curSize);
  $('input').css('font-size', curSize);
  $('fieldset').css('font-size', curSize);
  $('form').css('font-size', curSize);

  e.preventDefault();
};

/**
 * @function
 * @public
 *
 * @description
 * display the loader overlay on the selected page element
 *
 * @param {Object} element, page element to cover with the loading spinner
 * @param {Integer} options
 * @returns {}
 */
Interlock.UI.ajaxLoader = function (el, options) {
  var defaults = {
    bgColor: 'black',
    duration: 800,
    opacity: 0.2,
    classOveride: false,
    widthAdjustment: 0
  }
  this.options = $.extend(defaults, options);
  this.container = $(el);

  this.init = function() {
    var container = this.container;
    /* delete any other loader */
    this.remove();
    /* create the overlay */
    var overlay = $(document.createElement('div')).css({
      'background-color': this.options.bgColor,
      'opacity':this.options.opacity,
      'width':container.width() - this.options.widthAdjustment,
      'height':container.height(),
      'position':'absolute',
      'top':'0px',
      'left':'0px',
      'z-index':99999
    }).addClass('ajax_overlay');

    /* add an overriding class name to set new loader style */
    if (this.options.classOveride) {
      overlay.addClass(this.options.classOveride);
    }
    /* insert overlay and loader into DOM */
    container.append(
      overlay.append(
        $(document.createElement('div')).addClass('ajax_loader')
      ).fadeIn(this.options.duration)
    );
  };

  this.remove = function(){
    var overlay = this.container.children(".ajax_overlay");
    if (overlay.length) {
      overlay.fadeOut(this.options.classOveride, function() {
        overlay.remove();
      });
    }
  };

  this.init();
};

/**
 * @function
 * @public
 *
 * @description
 * convert an epoch to a properly formatted time string
 *
 * @param {Integer} epoch, element, page element to cover with the loading spinner
 * @param {Boolean} stripDate, strip the date part of the epoch and shows only the time
 *
 * @returns {String} time
 */
Interlock.UI.convertToTimeString = function(epoch, stripDate) {
  var formattedTimestamp;
  var timestamp = new Date(epoch * 1000);

  /* applies any timezone offset */
  timestamp.setMinutes(timestamp.getMinutes() - timestamp.getTimezoneOffset());

  if (stripDate) {
    formattedTimestamp = timestamp.toISOString().replace(/T/g, '  ').slice(11,20);
  } else {
    formattedTimestamp = timestamp.toISOString().replace(/T/g, '  ').slice(0,20);
  }

  return formattedTimestamp;
};

/**
 * @function
 * @public
 *
 * @description
 * convert numeric uptime in dd:hh:mm format
 *
 * @param {Integer} uptime
 *
 * @returns {String} uptime (dd:hh:mm)
 */
Interlock.UI.convertUptime = function(uptime) {
  var uptimeDays;
  var uptimeHours;
  var uptimeMins;
  var uptimeSecs;
  var uptime;

  var formattedUptime = 'up ';
  var pad = '00';

  uptimeDays = parseInt(uptime / (60 * 60 * 24));
  uptimeHours = parseInt(parseInt(uptime / (60 * 60)) - (uptimeDays * 24));
  uptimeMins = parseInt(parseInt(uptime / 60) - (uptimeDays * 60 * 24) - (uptimeHours * 60));
  uptimeSecs = parseInt(uptime - (uptimeMins * 60) - (uptimeDays * 60 * 60 * 24) - (uptimeHours * 60 * 60));

  if (uptimeDays > 0) {
    if (uptimeDays === 1) {
      uptime = uptimeDays + ' day';
    } else {
      uptime = uptimeDays + ' days';
    }

    formattedUptime += uptime + ', ' +
      pad.substring(uptimeHours.toString().length) + uptimeHours + ':' +
      pad.substring(uptimeMins.toString().length) + uptimeMins;
  } else if (uptimeHours > 0) {
    formattedUptime +=
      pad.substring(uptimeHours.toString().length) + uptimeHours + ':' +
      pad.substring(uptimeMins.toString().length) + uptimeMins;
  } else if (uptimeMins > 0) {
    formattedUptime += uptimeMins + ' min';
  } else {
    formattedUptime += uptimeSecs + ' sec';
  }

  return formattedUptime;
};

/**
 * @function
 * @public
 *
 * @description
 * return the current time in the format hh:mm
 *
 * @param {Integer} uptime
 *
 * @returns {String} currentTime (hh:mm)
 */
Interlock.UI.currentTime = function() {
  var pad = '00';
  var currentDate = new Date();

  var hours = currentDate.getHours().toString();
  var min = currentDate.getMinutes().toString();

  return (pad.substring(hours.length) + hours + ':' +
          pad.substring(min.length) + min);
};
