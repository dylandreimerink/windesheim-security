// If the close button inside a message is clicked close the message
$('.message .close')
  .on('click', function() {
    $(this)
      .closest('.message')
      .transition('fade')
    ;
  })
;

// Init a date only calendar on all inputs with the classes 'ui calendar'
$('.ui.calendar').each(function(){
    var settings = {}

    if( $(this).hasClass("date") ){
        settings.type = 'date'
        settings.formatter = {
            date: function (date, settings) {
                if (!date) return '';
                var day = date.getDate();
                var month = date.getMonth() + 1;
                var year = date.getFullYear();
                return day + '-' + month + '-' + year;
            }
        }
    }

    if( $(this).hasClass("date-time") ){
      settings.formatter = {
          date: function (date, settings) {
            if (!date) return '';
            // console.log(date)
            // var day = date.getDate();
            // var month = date.getMonth() + 1;
            // var year = date.getFullYear();
            // var seconds = date.getSeconds();
            // var minutes = date.get
            // var seconds = date.get
            // return day + '-' + month + '-' + year;
            return date.toLocaleDateString("nl-NL");
          },
          time: function (date, settings) {
            if (!date) return '';
            return date.toLocaleTimeString("nl-NL")
          }
      }
    }

    if( $(this).hasClass("year-first") ){
        settings.startMode = "year"
    }
    
    $(this).calendar(settings);
});

//Foreach semantic ui dropdown init
$('.dropdown').each(function(){
  $(this).dropdown();
});