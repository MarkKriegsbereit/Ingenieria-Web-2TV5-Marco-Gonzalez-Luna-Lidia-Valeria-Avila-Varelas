function validarFormulario(event) {
    const usuario = document.getElementById("usuario").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirmPassword").value.trim();

    const errorUsuario = document.getElementById("errorUsuario");
    const errorPassword = document.getElementById("errorPassword");
    const errorConfirm = document.getElementById("errorConfirmPassword");
    const mensajeExito = document.getElementById("mensajeExito");

    // Limpiar mensajes previos
    errorUsuario.textContent = "";
    errorPassword.textContent = "";
    errorConfirm.textContent = "";
    mensajeExito.textContent = "";

    let valido = true;
    
    // Regex estándar para email
    const regexCorreo = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!regexCorreo.test(usuario)) {
        errorUsuario.textContent = "Correo inválido. Ej: usuario@dominio.com";
        valido = false;
    }

    if (password.length < 8) {
        errorPassword.textContent = "La contraseña debe tener al menos 8 caracteres.";
        valido = false;
    }

    if (password !== confirmPassword) {
        errorConfirm.textContent = "Las contraseñas no coinciden.";
        valido = false;
    }

    // Si hay errores, cancelamos el envío
    if (!valido) {
        event.preventDefault();
        return false;
    }

    // Mensaje visual de éxito antes de que el servidor procese
    mensajeExito.textContent = "✔ Datos válidos. Procesando registro...";
    mensajeExito.style.color = "#00ff00"; // Verde lima brillante

    return true;
}