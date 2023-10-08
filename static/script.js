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
