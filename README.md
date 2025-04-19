

# 📡 Analizador de Protocolos de Última Milla (XDSL / PON)

## 📝 Descripción

Este programa permite analizar tramas de red capturadas en formato CSV (exportado desde Wireshark), enfocándose en protocolos de última milla como **XDSL** (PPPoE/PPP) y **PON** (GPON/EPON). A partir de los datos, genera un reporte en **HTML** con información relevante, explicaciones de campos y estadísticas útiles.

---

## 🛠️ Requisitos

- Python 3.x
- Archivo `.csv` exportado desde Wireshark
- Librería Python: `pandas`  
  *(Se instala automáticamente si no está presente)*

---

## 📥 Instalación

1. Clona este repositorio o descarga el archivo `analizador_tramas.py`.

2. Instala la dependencia necesaria ejecutando:

   ```bash
   pip install pandas
   ```

---

## 🚀 Uso

1. **Exporta las tramas desde Wireshark:**

   ```
   File > Export Packet Dissections > As CSV...
   ```

2. **Ejecuta el programa:**

   ```bash
   python analizador_tramas.py
   ```

3. **Sigue las instrucciones en consola:**

   - Ingresa la ruta del archivo CSV
   - Selecciona las columnas a analizar
   - Proporciona un nombre para el protocolo

4. **Resultado:**  
   Se generará un archivo HTML con el reporte detallado.

---

## 🔍 Funcionalidades

- ✅ Lista todas las columnas disponibles en el archivo CSV
- ✅ Permite seleccionar columnas específicas para el análisis
- ✅ Genera reportes HTML conservando el formato original
- ✅ Soporta protocolos XDSL (PPPoE/PPP) y PON (GPON/EPON)

---

## 📊 Columnas comunes a analizar

### Para XDSL / PPPoE:

- `frame.number` → Número de trama  
- `frame.time` → Marca de tiempo  
- `eth.type` → Tipo de trama Ethernet  
- `pppoe.code` → Código del mensaje PPPoE  
- `pppoe.type` → Tipo de mensaje PPPoE  
- `ppp.protocol` → Protocolo encapsulado en PPP  

### Para PON / GPON:

- `gpon.omci` → Mensajes OMCI  
- `gpon.port_id` → ID de puerto GPON  
- `gpon.onu_id` → Identificador de ONU  
- `gpon.gemport` → Puerto GEM asociado  

---

## 📂 Salida generada

- 🧾 **Archivo HTML** con:
  - Datos seleccionados
  - Metadatos del análisis
  - Explicación de campos
- 🔒 Formato del CSV original respetado

---




