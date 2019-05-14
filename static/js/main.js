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

    if( $(this).hasClass("year-first") ){
        settings.startMode = "year"
    }
    
    $(this).calendar(settings);
});
