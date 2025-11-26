// Cargar la librería de Google Charts y especificar que queremos el paquete 'gauge'
google.charts.load('current', {'packages':['gauge']});

// Cuando la librería esté lista, llamar a nuestra función para dibujar las gráficas
google.charts.setOnLoadCallback(inicializarGauges);

// Variables globales para guardar nuestras gráficas y datos
let chartAltitud, chartTemperatura, chartPresion;
let dataAltitud, dataTemperatura, dataPresion;

// Opciones de configuración para cada gráfica (puedes personalizarlas)
const opcionesAltitud = {
    width: 300, height: 300,
    redFrom: 900, redTo: 1000,
    yellowFrom: 750, yellowTo: 900,
    minorTicks: 5, max: 1000 // Altitud máxima esperada en metros
};
const opcionesTemperatura = {
    width: 300, height: 300,
    redFrom: 40, redTo: 60,
    yellowFrom: 30, yellowTo: 40,
    minorTicks: 5, min: -20, max: 60 // Rango de temperatura en °C
};
const opcionesPresion = {
    width: 300, height: 300,
    redFrom: 950, redTo: 980,
    yellowFrom: 980, yellowTo: 1000,
    minorTicks: 5, min: 900, max: 1100 // Rango de presión en hPa
};


function inicializarGauges() {
    // --- Inicializar los datos para cada gráfica ---
    dataAltitud = google.visualization.arrayToDataTable([
        ['Label', 'Value'],
        ['Altitud', 0]
    ]);
    dataTemperatura = google.visualization.arrayToDataTable([
        ['Label', 'Value'],
        ['Temp °C', 0]
    ]);
    dataPresion = google.visualization.arrayToDataTable([
        ['Label', 'Value'],
        ['Presión', 0]
    ]);

    // --- Crear una instancia de cada gráfica ---
    chartAltitud = new google.visualization.Gauge(document.getElementById('gauge_altitud'));
    chartTemperatura = new google.visualization.Gauge(document.getElementById('gauge_temperatura'));
    chartPresion = new google.visualization.Gauge(document.getElementById('gauge_presion'));

    // --- Dibujar las gráficas con valor inicial 0 ---
    chartAltitud.draw(dataAltitud, opcionesAltitud);
    chartTemperatura.draw(dataTemperatura, opcionesTemperatura);
    chartPresion.draw(dataPresion, opcionesPresion);

    // --- ¡La magia de la simulación en tiempo real! ---
    // Llamar a la función para obtener datos cada 3 segundos (3000 milisegundos)
    setInterval(actualizarDatos, 3000);
}

// Función que pide los datos al servidor y actualiza las gráficas
async function actualizarDatos() {
    console.log("Pidiendo datos nuevos...");
    try {
        // Hacemos la llamada al archivo PHP que creamos
        const response = await fetch('api_gettrama.php');
        const datos = await response.json();

        if (datos.error) {
            console.error(datos.error);
            return;
        }
        
        console.log("Datos recibidos:", datos);

        // --- Actualizar los valores en nuestras tablas de datos ---
        dataAltitud.setValue(0, 1, datos.altitud);
        dataTemperatura.setValue(0, 1, datos.temperatura);
        dataPresion.setValue(0, 1, datos.presion);

        // --- Volver a dibujar las gráficas con los nuevos valores ---
        chartAltitud.draw(dataAltitud, opcionesAltitud);
        chartTemperatura.draw(dataTemperatura, opcionesTemperatura);
        chartPresion.draw(dataPresion, opcionesPresion);

    } catch (error) {
        console.error('Error al obtener los datos de la trama:', error);
    }
}