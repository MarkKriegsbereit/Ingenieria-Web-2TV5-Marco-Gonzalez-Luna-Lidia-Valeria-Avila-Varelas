function validarFormulario(event) {
    const usuario = document.getElementById("usuario").value.trim();
    const password = document.getElementById("password").value.trim();

    const errorUsuario = document.getElementById("errorUsuario");
    const errorPassword = document.getElementById("errorPassword");

    // Limpiar errores previos
    errorUsuario.textContent = "";
    errorPassword.textContent = "";

    let valido = true;

    // Regex estándar para email
    const regexCorreo = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    if (!regexCorreo.test(usuario)) {
        errorUsuario.textContent = "Formato de correo inválido";
        valido = false;
    }

    if (password.length < 1) {
        errorPassword.textContent = "Por favor ingresa tu contraseña";
        valido = false;
    } else if (password.length < 8) {
        // Opcional: advertencia visual, aunque el servidor es quien decide
        errorPassword.textContent = "La contraseña debe tener al menos 8 caracteres";
        valido = false;
    }

    if (!valido) {
        event.preventDefault();
        return false;
    }
    return true;
}