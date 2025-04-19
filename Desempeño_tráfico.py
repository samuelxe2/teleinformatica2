import time
import requests
from ftplib import FTP
import os
import pyshark
import matplotlib.pyplot as plt
from collections import defaultdict

class EvaluadorDesempeno:
    def __init__(self):
        pass

    def medir_velocidad_http(self, url):
        """Mide la velocidad de descarga de un archivo desde un servidor HTTP/HTTPS."""
        try:
            print(f"Iniciando descarga desde {url}...")
            inicio = time.time()
            response = requests.get(url, stream=True)
            total_bytes = 0

            for chunk in response.iter_content(chunk_size=1024):
                total_bytes += len(chunk)

            fin = time.time()
            duracion = fin - inicio
            velocidad = (total_bytes / 1024 / 1024) / duracion  # MB/s
            print(f"Descarga completada: {total_bytes / 1024 / 1024:.2f} MB en {duracion:.2f} segundos.")
            print(f"Velocidad promedio: {velocidad:.2f} MB/s")
            return velocidad
        except Exception as e:
            print(f"Error al medir velocidad HTTP: {str(e)}")
            return None

    def medir_velocidad_ftp(self, servidor, usuario, contrasena, archivo):
        """Mide la velocidad de descarga de un archivo desde un servidor FTP."""
        try:
            print(f"Conectando al servidor FTP {servidor}...")
            ftp = FTP(servidor)
            ftp.login(user=usuario, passwd=contrasena)
            inicio = time.time()
            total_bytes = 0

            with open("temp_ftp_file", "wb") as f:
                def callback(data):
                    nonlocal total_bytes
                    total_bytes += len(data)
                    f.write(data)

                ftp.retrbinary(f"RETR {archivo}", callback)

            fin = time.time()
            ftp.quit()
            os.remove("temp_ftp_file")  # Eliminar archivo temporal

            duracion = fin - inicio
            velocidad = (total_bytes / 1024 / 1024) / duracion  # MB/s
            print(f"Descarga completada: {total_bytes / 1024 / 1024:.2f} MB en {duracion:.2f} segundos.")
            print(f"Velocidad promedio: {velocidad:.2f} MB/s")
            return velocidad
        except Exception as e:
            print(f"Error al medir velocidad FTP: {str(e)}")
            return None

    def medir_velocidad_streaming(self, url, duracion_segundos=10):
        """Mide la velocidad de transferencia de un flujo de datos (streaming)."""
        try:
            print(f"Iniciando prueba de streaming desde {url} por {duracion_segundos} segundos...")
            inicio = time.time()
            response = requests.get(url, stream=True)
            total_bytes = 0

            for chunk in response.iter_content(chunk_size=1024):
                total_bytes += len(chunk)
                if time.time() - inicio > duracion_segundos:
                    break

            fin = time.time()
            duracion = fin - inicio
            velocidad = (total_bytes / 1024 / 1024) / duracion  # MB/s
            print(f"Streaming completado: {total_bytes / 1024 / 1024:.2f} MB en {duracion:.2f} segundos.")
            print(f"Velocidad promedio: {velocidad:.2f} MB/s")
            return velocidad
        except Exception as e:
            print(f"Error al medir velocidad de streaming: {str(e)}")
            return None


class AnalizadorPCAP:
    def __init__(self):
        pass

    def analizar_y_graficar(self, pcap_file, puerto_servicio):
        """Analiza un archivo PCAP y genera gráficos relacionados con el tráfico TCP."""
        cap = pyshark.FileCapture(pcap_file, display_filter=f'tcp.port == {puerto_servicio}')

        bytes_por_segundo = defaultdict(int)
        retransmisiones = []
        tamanos_paquetes = []

        tiempo_inicio = None
        primer_request = None
        primera_respuesta = None
        handshake_delay = None

        for pkt in cap:
            try:
                tiempo_pkt = float(pkt.sniff_timestamp)
                segundo = int(tiempo_pkt)
                longitud = int(pkt.length)

                if tiempo_inicio is None:
                    tiempo_inicio = tiempo_pkt

                bytes_por_segundo[segundo] += longitud
                tamanos_paquetes.append(longitud)

                if 'HTTP' in pkt:
                    if 'GET' in str(pkt.http.request_method):
                        primer_request = tiempo_pkt
                    elif '200' in str(pkt.http.response_code) and primer_request:
                        primera_respuesta = tiempo_pkt - primer_request

                if hasattr(pkt.tcp, 'analysis_retransmission'):
                    retransmisiones.append(tiempo_pkt)

                if hasattr(pkt.tcp, 'flags_syn') and pkt.tcp.flags_syn == '1':
                    handshake_syn_time = tiempo_pkt
                if hasattr(pkt.tcp, 'flags_ack') and pkt.tcp.flags_ack == '1' and hasattr(pkt.tcp, 'analysis_ack_rtt'):
                    handshake_delay = float(pkt.tcp.analysis_ack_rtt)

            except Exception:
                continue

        cap.close()

        # --- 📊 GRAFICAR ---
        tiempo_relativo = sorted(bytes_por_segundo.keys())
        velocidad_mbps = [bytes_por_segundo[t] * 8 / 1_000_000 for t in tiempo_relativo]  # Mbps

        # 📈 1. Velocidad de transferencia
        plt.figure(figsize=(10, 5))
        plt.plot([t - tiempo_inicio for t in tiempo_relativo], velocidad_mbps, marker='o')
        plt.title("Velocidad de transferencia por segundo")
        plt.xlabel("Tiempo (s)")
        plt.ylabel("Velocidad (Mbps)")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig("velocidad_transferencia.png")
        plt.show()

        # 📈 2. Retransmisiones acumuladas
        if retransmisiones:
            tiempos_retrans = [t - tiempo_inicio for t in retransmisiones]
            acumuladas = list(range(1, len(tiempos_retrans)+1))
            plt.figure(figsize=(10, 5))
            plt.step(tiempos_retrans, acumuladas, where='post')
            plt.title("Retransmisiones TCP acumuladas")
            plt.xlabel("Tiempo (s)")
            plt.ylabel("Retransmisiones")
            plt.grid(True)
            plt.tight_layout()
            plt.savefig("retransmisiones.png")
            plt.show()

        # 📈 3. Distribución de tamaños de paquetes
        plt.figure(figsize=(10, 5))
        plt.hist(tamanos_paquetes, bins=20, color='skyblue', edgecolor='black')
        plt.title("Distribución de tamaños de paquetes TCP")
        plt.xlabel("Tamaño (bytes)")
        plt.ylabel("Frecuencia")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig("tamano_paquetes.png")
        plt.show()

        # --- 🧾 RESULTADOS ---
        total_bytes = sum(bytes_por_segundo.values())
        tiempo_total = max(tiempo_relativo) - int(tiempo_inicio)
        velocidad_promedio = (total_bytes * 8 / 1_000_000) / tiempo_total if tiempo_total else 0

        return {
            "Tiempo total (s)": tiempo_total,
            "Velocidad promedio (Mbps)": round(velocidad_promedio, 3),
            "Retransmisiones TCP": len(retransmisiones),
            "TTFB (s)": round(primera_respuesta, 3) if primera_respuesta else "No detectado",
            "Delay Handshake (s)": round(handshake_delay, 6) if handshake_delay else "No detectado",
        }


def main():
    print("\n--- Evaluación de Desempeño de Tráfico ---")
    print("1. Medir velocidad HTTP")
    print("2. Medir velocidad FTP")
    print("3. Medir velocidad de Streaming")
    print("4. Analizar archivo PCAP")
    opcion = input("Seleccione una opción: ").strip()

    if opcion == "1":
        url = input("Ingrese la URL del archivo HTTP/HTTPS: ").strip()
        evaluador = EvaluadorDesempeno()
        evaluador.medir_velocidad_http(url)
    elif opcion == "2":
        servidor = input("Ingrese el servidor FTP: ").strip()
        usuario = input("Ingrese el usuario FTP: ").strip()
        contrasena = input("Ingrese la contraseña FTP: ").strip()
        archivo = input("Ingrese el nombre del archivo a descargar: ").strip()
        evaluador = EvaluadorDesempeno()
        evaluador.medir_velocidad_ftp(servidor, usuario, contrasena, archivo)
    elif opcion == "3":
        url = input("Ingrese la URL del flujo de streaming: ").strip()
        duracion = int(input("Ingrese la duración de la prueba en segundos: ").strip())
        evaluador = EvaluadorDesempeno()
        evaluador.medir_velocidad_streaming(url, duracion)
    elif opcion == "4":
        pcap_file = input("Ingrese la ruta del archivo PCAP: ").strip()
        puerto = input("Ingrese el puerto del servicio (por ejemplo, 80 para HTTP): ").strip()

        try:
            puerto = int(puerto)
        except ValueError:
            print("El puerto debe ser un número.")
            return

        analizador = AnalizadorPCAP()
        resultados = analizador.analizar_y_graficar(pcap_file, puerto)

        print("\n--- RESULTADOS DEL ANÁLISIS ---")
        for clave, valor in resultados.items():
            print(f"{clave}: {valor}")
    else:
        print("Opción no válida.")


if __name__ == "__main__":
    main()