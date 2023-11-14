// Check if we're in the context of the browser extension
var isExtensionContext = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id;

document.addEventListener("DOMContentLoaded", function() {
    // Elements
    var keywordInput = document.getElementById('keyword-input');
    var lengthInput = document.getElementById('length-input');
    var numbersCheckbox = document.getElementById('numbers');
    var symbolsCheckbox = document.getElementById('symbols');
    var generateBtn = document.getElementById('generate-btn');
    var generatedPasswordInput = document.getElementById('generated-password');
    var copyBtn = document.getElementById('copy-btn');
    var strengthIndicator = document.getElementById('strength-indicator');


    // Event Listener for Generate Button
generateBtn.addEventListener('click', function() {
    var keyword = keywordInput.value;
    var length = parseInt(lengthInput.value);
    var useNumbers = numbersCheckbox.checked;
    var useSymbols = symbolsCheckbox.checked;

    // Validation: At least one of "useNumbers" or "useSymbols" must be true
    if (!useNumbers && !useSymbols) {
        alert("Please select at least one option: Include Numbers or Include Symbols.");
        return;  // Exit the function early
    }


    var password = generatePassword(keyword, length, useNumbers, useSymbols);
    generatedPasswordInput.value = password;

    var strength = checkPasswordStrength(password);
    updateStrengthIndicator(strength);
});


generatedPasswordInput.addEventListener('input', function() {
    var currentPassword = generatedPasswordInput.value;
    var strength = checkPasswordStrength(currentPassword);
    updateStrengthIndicator(strength);
});

    // Event Listener for Copy Button
    copyBtn.addEventListener('click', function() {
        generatedPasswordInput.select();
        document.execCommand('copy');
        copyBtn.innerHTML = '<i class="bi bi-clipboard-check"></i>';
        setTimeout(function() {
            copyBtn.innerHTML = '<i class="bi bi-clipboard"></i>';
        }, 2000); // Reset icon after 2 seconds
    });

    // Event Listener for real-time password strength check
    generatedPasswordInput.addEventListener('input', function() {
    var currentPassword = generatedPasswordInput.value;
    var strength = checkPasswordStrength(currentPassword);
    updateStrengthIndicator(strength);
});

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
            if (i % 3 === 0 && i/3 < keyword.length) {
                password += keyword.charAt(i/3);
            } else {
                password += characters.charAt(Math.floor(Math.random() * characters.length));
            }
        }

        return password;
    }

    function checkPasswordStrength(password) {
        var strength = {status: 'Weak', score: 0, color: 'red'};

        if (password.length >= 8) strength.score += 1;
        if (/[0-9]/.test(password)) strength.score += 1;
        if (/[A-Z]/.test(password)) strength.score += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength.score += 1;

        if (strength.score === 4) {
            strength.status = 'Very Strong';
            strength.color = 'green';
        } else if (strength.score === 3) {
            strength.status = 'Strong';
            strength.color = 'lightgreen';
        } else if (strength.score === 2) {
            strength.status = 'Moderate';
            strength.color = 'orange';
        }

        return strength;
    }

    function updateStrengthIndicator(strength) {
        strengthIndicator.innerHTML = `
            <div class="progress" style="height: 20px;">
                <div class="progress-bar" role="progressbar" style="width: ${strength.score * 25}%; background-color: ${strength.color};" aria-valuenow="${strength.score}" aria-valuemin="0" aria-valuemax="4"></div>
            </div>
            <p class="mt-2">${strength.status}</p>
        `;
    }
});

