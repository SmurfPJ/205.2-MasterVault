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
