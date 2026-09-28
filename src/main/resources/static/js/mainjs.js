$(document).ready(function () {

    if ($('#profile').length) {
        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            beforeSend: function (xhr) {
                if (localStorage.token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.token);
                }
            },
            success: function (data) {
                $('#profile').text(data.fullName + ' (' + data.email + ')');
                if (data.images) {
                    $('#images').attr('src', data.images).show();
                }
            },
            error: function () {
                alert('Sorry, you are not logged in.');
                localStorage.clear();
                window.location.href = '/login';
            }
        });
    }

    $('#logout').click(function () {
        localStorage.clear();
        window.location.href = '/login';
    });

    $('#Login').click(function () {
        var basicInfo = JSON.stringify({
            email: document.getElementById('email').value,
            password: document.getElementById('password').value
        });
        $.ajax({
            type: 'POST',
            url: '/auth/login',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            data: basicInfo,
            success: function (data) {
                localStorage.token = data.token;
                window.location.href = '/user/profile';
            },
            error: function () {
                alert('Login Failed');
            }
        });
    });
});
