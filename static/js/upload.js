$(document).ready(function() {
    
    $('form').on('submit', function(event) {

        event.preventDefault();

        var formData = new formData($('form')[0]);

        $.ajax({
            xhr : function() {
                var xhr = new window.XMLHttpRequest();

                xhr.upload.addEventListener('progress', function(e) {

                    if (e.lengthComputable) {
                        console.log('Bytes loaded: ' + e.loaded);
                        console.log('Total Size: ' + e.total);
                        console.log('Percentage Uploaded: ' + (e.loaded / e.total))

                        var percent = Math.round((e.loaded / e.total)*100);

                        $('#progress-bar').attr('aria-valuenow', percent).css('width', percent + '%').text('width', percent + '%');
                    }

                });

                return xhr;

            },
            type : 'POST',
            data : formData,
            processData : false,
            contentType : false,
            success : function () {
                alert('Image uploaded and analysed');

            }
        });
        
    });
});