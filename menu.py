import os

def ejecutar_script():
    """Ejecuta el script de análisis de archivos CSV (script.py)."""
    print("\n--- Análisis de Protocolos de Última Milla (CSV) ---")
    os.system("python script.py")

def ejecutar_desempeno_trafico():
    """Ejecuta el script de evaluación de desempeño del tráfico (Desempeño_tráfico.py)."""
    print("\n--- Evaluación de Desempeño del Tráfico TCP/IP ---")
    os.system("python Desempeño_tráfico.py")

def menu_principal():
    while True:
        print("\n--- Menú Principal ---")
        print("1. Analizar archivos CSV (script.py)")
        print("2. Evaluar desempeño del tráfico TCP/IP (Desempeño_tráfico.py)")
        print("3. Salir")
        
        opcion = input("Seleccione una opción: ").strip()
        
        if opcion == "1":
            ejecutar_script()
        elif opcion == "2":
            ejecutar_desempeno_trafico()
        elif opcion == "3":
            print("Saliendo del programa...")
            break
        else:
            print("Opción no válida. Intente nuevamente.")

if __name__ == "__main__":
    menu_principal()