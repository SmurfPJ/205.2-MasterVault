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

    // Check the initial password strength
    var initialPassword = document.getElementById('generated-password').value;
    if (initialPassword) {
        checkPasswordStrength(initialPassword);
    }
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

function updateRangeLabel() {
    var rangeValue = document.getElementById('lockRange').value;
    document.getElementById('lockRangeLabel').innerText = rangeValue * 10 + ' minutes';
}

function toggleSlider() {
    var lockSwitch = document.getElementById('lockSwitch').checked;
    var lockRange = document.getElementById('lockRange');
    lockRange.disabled = !lockSwitch;
}

function validateForm() {
    var useNumbers = document.getElementById('numbers').checked;
    var useSymbols = document.getElementById('symbols').checked;

    if (!useNumbers && !useSymbols) {
        alert("Please select at least one option: Include Numbers or Include Symbols.");
        return false;
    }
    return true;
}

function checkPasswordStrength(password) {
    var strength = {
        status: 'Weak',
        score: 0,
        color: 'red'
    };

    if (password.length >= 5) {
        strength.score += 1;
    }
    if (/[0-9]/.test(password)) {
        strength.score += 1;
    }
    if (/[A-Z]/.test(password)) {
        strength.score += 1;
    }
    if (/[^a-zA-Z0-9]/.test(password)) {
        strength.score += 1;
    }

    // Update status and color based on score
    if (strength.score === 4) {
        strength.status = 'Very Strong';
        strength.color = 'green';
    } else if (strength.score === 3) {
        strength.status = 'Strong';
        strength.color = 'lightgreen';
    } else if (strength.score === 2) {
        strength.status = 'Moderate';
        strength.color = 'orange';
    } else {
        strength.status = 'Weak';
        strength.color = 'red';
    }

    document.getElementById('password-strength-bar').style.width = (strength.score * 25) + '%';
    document.getElementById('password-strength-bar').style.backgroundColor = strength.color;
    document.getElementById('password-strength-text').innerText = strength.status;
}

function generatePassword(keyword, length, useNumbers, useSymbols) {
    var characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" + keyword;

    if (useNumbers) {
        characters += "0123456789";
    }
    if (useSymbols) {
        characters += "!@#$%^&*()_-+=<>?/[]{}|";
    }

    var password = "";
    for (var i = 0; i < length; i++) {
        // Every third character is from the keyword
        if (i % 3 === 0 && i/3 < keyword.length) {
            password += keyword.charAt(i/3);
        } else {
            password += characters.charAt(Math.floor(Math.random() * characters.length));
        }
    }

    return password;
}

function refreshPassword() {
    var keyword = document.getElementById('keyword-input').value;
    var length = document.getElementById('length-input').value;
    var useNumbers = document.getElementById('numbers').checked;
    var useSymbols = document.getElementById('symbols').checked;

    var newPassword = generatePassword(keyword, length, useNumbers, useSymbols);
    document.getElementById('generated-password').value = newPassword;

    // Update the password strength indicator real-time as password refreshes
    checkPasswordStrength(newPassword);
}

function copyToClipboard() {
    // Copy password to clipboard
    var passwordField = document.getElementById('generated-password');
    passwordField.select();
    document.execCommand('copy');

    // Change icon to clipboard-check
    document.getElementById('clipboard-icon').className = 'bi bi-clipboard-check';


    setTimeout(function () {
        document.getElementById('clipboard-icon').className = 'bi bi-clipboard';
    }, 2000); //2 seconds

}