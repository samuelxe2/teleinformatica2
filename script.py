import pandas as pd
from datetime import datetime
import sys
import os

class AnalizadorCSVUltimaMilla:
    def __init__(self, archivo_csv):
        self.archivo_csv = archivo_csv
        
    def mostrar_columnas(self):
        """Muestra las columnas disponibles en el CSV"""
        try:
            df = pd.read_csv(self.archivo_csv)
            print("\nColumnas disponibles en el archivo CSV:")
            for i, columna in enumerate(df.columns, 1):
                print(f"{i}. {columna}")
            return df.columns.tolist()
        except Exception as e:
            print(f"Error al leer el archivo CSV: {str(e)}")
            return []
    
    def analizar_tramas(self, columnas_seleccionadas):
        """Analiza las columnas seleccionadas del CSV"""
        try:
            df = pd.read_csv(self.archivo_csv)
            
            # Verificar que las columnas seleccionadas existan
            columnas_validas = [col for col in columnas_seleccionadas if col in df.columns]
            
            if not columnas_validas:
                print("Ninguna de las columnas seleccionadas existe en el CSV.")
                return None
                
            return df[columnas_validas]
            
        except Exception as e:
            print(f"Error al analizar CSV: {str(e)}")
            return None
    
    def generar_reporte(self, df, protocolo, archivo_salida=None):
        """Genera un reporte HTML con las tramas analizadas"""
        if df is None or df.empty:
            print("No hay datos para generar reporte.")
            return
            
        if archivo_salida is None:
            nombre_base = os.path.splitext(self.archivo_csv)[0]
            archivo_salida = f"{nombre_base}_reporte_{protocolo}.html"
        
        html = f"""
        <html>
        <head>
            <title>Reporte de {protocolo.upper()}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h1>Reporte de análisis de tramas</h1>
            <p>Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Archivo analizado: {self.archivo_csv}</p>
            <p>Protocolo: {protocolo.upper()}</p>
            {df.to_html(classes='dataframe', escape=False, index=False)}
        </body>
        </html>
        """
        
        with open(archivo_salida, 'w', encoding='utf-8') as f:
            f.write(html)
            
        print(f"\nReporte generado en {archivo_salida}")

def main():
    print("""
    ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ 
    ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗
    █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝
    ██╔══╝  ██║╚██╗██║██║     ██╔═══╝   ╚██╔╝  ██╔═══╝ 
    ███████╗██║ ╚████║╚██████╗██║        ██║   ██║     
    ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝        ╚═╝   ╚═╝     
    """)
    
    print("Analizador de Protocolos de Última Milla")
    print("Versión para archivos CSV exportados desde Wireshark\n")
    
    # Solicitar archivo CSV
    archivo_csv = "C:\\Users\\admin\\Desktop\\teleinformatica2\\teleCvs.csv"
    
    # Verificar si el archivo existe
    if not os.path.isfile(archivo_csv):
        print(f"\nError: No se encontró el archivo {archivo_csv}")
        sys.exit(1)
    
    # Crear analizador y mostrar columnas
    analizador = AnalizadorCSVUltimaMilla(archivo_csv)
    columnas = analizador.mostrar_columnas()
    
    if not columnas:
        sys.exit(1)
    
    # Seleccionar columnas a analizar
    print("\nIngresa los números de las columnas que deseas analizar (separados por comas):")
    seleccion = input("> ").strip()
    
    try:
        indices = [int(i.strip()) - 1 for i in seleccion.split(',')]
        columnas_seleccionadas = [columnas[i] for i in indices if 0 <= i < len(columnas)]
    except:
        print("Selección no válida.")
        sys.exit(1)
    
    if not columnas_seleccionadas:
        print("No se seleccionaron columnas válidas.")
        sys.exit(1)
    
    # Seleccionar protocolo (solo para el nombre del reporte)
    protocolo = input("\nNombre del protocolo (para el reporte): ").strip()
    
    # Analizar y generar reporte
    df = analizador.analizar_tramas(columnas_seleccionadas)
    if df is not None:
        print("\nVista previa de los datos:")
        print(df.head())
        
        analizador.generar_reporte(df, protocolo)
        
        print("\nAnálisis completado. Revise el archivo de reporte generado.")

if __name__ == "__main__":
    main()