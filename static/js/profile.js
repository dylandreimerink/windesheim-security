//When the value of the 'Two factor authentication method' dropdown changes
$("#two-factor-auth-modal select[name='2fa-method']").change(changeTwoFactorMethod);
$("#submit-2fa").on("click", submit2FA);
$("#show-2fa-btn").on("click", () => {
    $('#two-factor-auth-modal').modal({
        'onApprove': () => {
            return false;
        }
    }).modal('show');
});

function loadTOTPQR() {
    fetch("/2fa/totp", {
        method: "POST",
    }).then(function(response){
        return response.blob();
    }).then(function(imgBlob){
        var urlCreator = window.URL || window.webkitURL;
        var imageUrl = urlCreator.createObjectURL(imgBlob);
        $("#totp-qr").attr("src", imageUrl);
        $("#totp").show();
        $("#u2f").hide();
    });
}

function changeTwoFactorMethod(e) {
    switch( e.target.value ) {
        case 'totp':
            loadTOTPQR();
            break;
        case 'u2f':
            $("#totp").hide();
            $("#u2f").show();
            break;
    }
}

function submit2FA(e) {
    var method = $("#two-factor-auth-modal select[name='2fa-method']").val();
    switch(method) {
        case 'totp':
            var verifyCode = $("#totp-verify-code").val();
            fetch("/2fa/totp/verify", {
                method: "POST",
                headers: {
                    "Content-type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                body: 'code=' + encodeURIComponent(verifyCode)
            }).then(resp => {
                if( resp.status == 200 ){
                    $("#two-factor-auth-modal").modal("hide");
                    $("#positive-message").find("span").text("Two factor authentication token successfully set, please login again. You will be redirected to the login page in 5 seconds");
                    $("#positive-message").removeClass("hidden");
                    window.setTimeout(() => {
                        window.location = "/login";
                    }, 5000);
                } else {   
                    loadTOTPQR();
                    resp.text().then(text => {
                        $("#two-factor-auth-error").find("span").text(text);
                        $("#two-factor-auth-error").removeClass("hidden");
                    })
                }
            });
            break;
        case 'u2f':
            
    }
}