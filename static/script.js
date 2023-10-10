document.addEventListener("DOMContentLoaded", function() {
    const form = document.querySelector("form");
    form.addEventListener("submit", function(event) {
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;
        if (!email || !password) {
            alert("Email and password are required!");
            event.preventDefault();
        }
    });
});

//login & signup password toggle button//
function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const togglePasswordIcon = document.getElementById('togglePasswordIcon');
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        togglePasswordIcon.className = 'bi bi-eye-slash';
    } else {
        passwordInput.type = 'password';
        togglePasswordIcon.className = 'bi bi-eye';
    }
}

function toggleConfirmPasswordVisibility() {
    const confirmPasswordInput = document.getElementById('confirm_password');
    const toggleConfirmPasswordIcon = document.getElementById('toggleConfirmPasswordIcon');
    if (confirmPasswordInput.type === 'password') {
        confirmPasswordInput.type = 'text';
        toggleConfirmPasswordIcon.className = 'bi bi-eye-slash';
    } else {
        confirmPasswordInput.type = 'password';
        toggleConfirmPasswordIcon.className = 'bi bi-eye';
    }
}

function checkPasswordMatch() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const passwordMatchMessage = document.getElementById('passwordMatchMessage');

    if (password === confirmPassword) {
        passwordMatchMessage.style.color = 'green';
        passwordMatchMessage.innerText = 'Passwords match';
    } else {
        passwordMatchMessage.style.color = 'red';
        passwordMatchMessage.innerText = 'Passwords do not match';
    }
}


//master password toggle//
function toggleMasterPasswordVisibility() {
    const passwordInput = document.getElementById('master_password');
    const togglePasswordIcon = document.getElementById('toggleMasterPasswordIcon');
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        togglePasswordIcon.className = 'bi bi-eye-slash';
    } else {
        passwordInput.type = 'password';
        togglePasswordIcon.className = 'bi bi-eye';
    }
}

function toggleConfirmMasterPasswordVisibility() {
    const confirmMasterPasswordInput = document.getElementById('confirmMaster_password');
    const toggleConfirmMasterPasswordIcon = document.getElementById('toggleConfirmMasterPasswordIcon');
    if (confirmMasterPasswordInput.type === 'password') {
        confirmMasterPasswordInput.type = 'text';
        toggleConfirmMasterPasswordIcon.className = 'bi bi-eye-slash';
    } else {
        confirmMasterPasswordInput.type = 'password';
        toggleConfirmMasterPasswordIcon.className = 'bi bi-eye';
    }
}

function checkMasterPasswordMatch() {
    const masterPassword = document.getElementById('master_password').value;
    const confirmMasterPassword = document.getElementById('confirmMaster_password').value;
    const passwordMatchMessage = document.getElementById('passwordMatchMessage');

    if (masterPassword === confirmMasterPassword) {
        passwordMatchMessage.style.color = 'green';
        passwordMatchMessage.innerText = 'Passwords match';
    } else {
        passwordMatchMessage.style.color = 'red';
        passwordMatchMessage.innerText = 'Passwords do not match';
    }
}