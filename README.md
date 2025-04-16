📡 Analizador de Protocolos de Última Milla (XDSL/PON)
📝 Descripción
Este programa analiza tramas de red capturadas en formato CSV (exportadas desde Wireshark) para protocolos de última milla como XDSL (PPPoE/PPP) y PON (GPON/EPON). Genera reportes HTML con los datos relevantes y explicaciones de los campos de protocolo.

🛠️ Requisitos
Python 3.x instalado

Archivo CSV exportado desde Wireshark

Librerías Python:

pandas

(Se instalan automáticamente al ejecutar por primera vez)

📥 Instalación
Clona el repositorio o descarga el archivo analizador_tramas.py

Instala las dependencias:

bash
Copy
pip install pandas
🚀 Uso
Exporta tus tramas desde Wireshark:

File > Export Packet Dissections > As CSV...

Ejecuta el programa:

bash
Copy
python analizador_tramas.py
Sigue las instrucciones:

Ingresa la ruta a tu archivo CSV

Selecciona las columnas a analizar

Proporciona un nombre para el protocolo

El programa generará un reporte HTML con los resultados

🔍 Funcionalidades
✅ Lista todas las columnas disponibles en el CSV

✅ Permite seleccionar columnas específicas para analizar

✅ Genera reportes HTML con los datos seleccionados

✅ Soporta tanto XDSL (PPPoE/PPP) como PON (GPON/EPON)

📊 Columnas comunes a buscar
Para XDSL/PPPoE:
frame.number - Número de trama

frame.time - Hora de captura

eth.type - Tipo de trama Ethernet

pppoe.code - Código PPPoE

pppoe.type - Tipo de mensaje PPPoE

ppp.protocol - Protocolo encapsulado en PPP

Para PON/GPON:
gpon.omci - Mensajes OMCI

gpon.port_id - ID de puerto GPON

gpon.onu_id - Identificador de ONU

gpon.gemport - Puerto GEM

📂 Estructura de salida
El programa genera:

Un reporte HTML con los datos analizados

Conserva el formato original del CSV

Incluye metadatos sobre el análisis

🐛 Solución de problemas
Si el programa no encuentra columnas relevantes:

Verifica que el archivo CSV contenga datos

Revisa los nombres de las columnas en el CSV

Exporta nuevamente desde Wireshark asegurándote de incluir todos los campos
