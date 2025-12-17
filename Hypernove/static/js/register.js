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
    
    // 1. Validar Correo
    const regexCorreo = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regexCorreo.test(usuario)) {
        errorUsuario.textContent = "Correo inválido. Ej: usuario@dominio.com";
        valido = false;
    }

    // 2. Validar Contraseña (Complejidad)
    // Explicación de los Regex:
    // \d busca un número
    // [!@#$%^&*(),.?":{}|<>] busca un símbolo especial
    const tieneNumero = /\d/.test(password);
    const tieneSimbolo = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < 8) {
        errorPassword.textContent = "Mínimo 8 caracteres.";
        valido = false;
    } else if (!tieneNumero) {
        errorPassword.textContent = "Debe incluir al menos un número.";
        valido = false;
    } else if (!tieneSimbolo) {
        errorPassword.textContent = "Debe incluir al menos un símbolo (!@#$...).";
        valido = false;
    }

    // 3. Validar Coincidencia
    if (password !== confirmPassword) {
        errorConfirm.textContent = "Las contraseñas no coinciden.";
        valido = false;
    }

    // Si NO es válido, detenemos el envío
    if (!valido) {
        event.preventDefault();
        return false;
    }

    // Mensaje visual de éxito
    mensajeExito.textContent = "✔ Datos válidos. Procesando registro...";
    mensajeExito.style.color = "#00ffcc"; // Color Hypernova

    return true;
}