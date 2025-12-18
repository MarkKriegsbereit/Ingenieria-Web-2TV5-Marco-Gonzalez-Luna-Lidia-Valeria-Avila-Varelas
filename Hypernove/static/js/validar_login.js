document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('.login-form');
    const passwordInput = document.getElementById('password');
    const emailInput = document.getElementById('usuario');
    const errorPassword = document.getElementById('errorPassword');
    const errorUsuario = document.getElementById('errorUsuario');

    // Regex: 8+ caracteres, 1 número, 1 símbolo
    const passwordRegex = /^(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;
    // Regex simple para email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    function validarContrasena() {
        if (passwordInput.value === "") {
            errorPassword.textContent = "";
            passwordInput.style.borderColor = "var(--color-gris-borde)";
            return true; 
        }

        if (!passwordRegex.test(passwordInput.value)) {
            errorPassword.textContent = "Contraseña inválida (mín. 8 caracteres, número y símbolo).";
            passwordInput.style.borderColor = "#dc3545";
            return false;
        } else {
            errorPassword.textContent = "";
            passwordInput.style.borderColor = "#28a745";
            return true;
        }
    }

    function validarEmail() {
        if (emailInput.value === "") {
            errorUsuario.textContent = "";
            return true;
        }
        if (!emailRegex.test(emailInput.value)) {
            errorUsuario.textContent = "Introduce un correo electrónico válido.";
            return false;
        } else {
            errorUsuario.textContent = "";
            return true;
        }
    }

    // Validar en tiempo real
    passwordInput.addEventListener('input', validarContrasena);
    emailInput.addEventListener('input', validarEmail);

    // Validación final antes de enviar
    window.validarFormulario = function(event) {
        const isPassValid = validarContrasena();
        const isEmailValid = validarEmail();

        if (!isPassValid || !isEmailValid) {
            event.preventDefault(); // Detiene el envío al servidor
            return false;
        }
        return true;
    };
});