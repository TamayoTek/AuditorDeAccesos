from abc import ABC, abstractmethod
import requests

class Comprobacion(ABC):
    def __init__(self, nombre: str):
        self._nombre = nombre

    @property
    def nombre(self) -> str:
        return self._nombre

    @abstractmethod
    def ejecutar(self) -> list[str]:
        """Debe devolver una lista de alertas (strings)."""
        pass

class ComprobacionIntentosFallidos(Comprobacion):
    def __init__(self, nombre: str, ruta_fichero: str, umbral: int = 3):
        super().__init__(nombre)
        self._ruta_fichero = ruta_fichero
        self._umbral = umbral

    def ejecutar(self) -> list[str]:
        alertas = []
        conteo_fallos = {}

        try:
            with open(self._ruta_fichero, 'r', encoding='utf-8') as archivo:
                for linea in archivo:
                    if "RESULTADO=FALLIDO" in linea:
                        partes = linea.strip().split()
                        usuario = ""
                        ip = ""
                        for parte in partes:
                            if parte.startswith("USER="):
                                usuario = parte.split("=")[1]
                            elif parte.startswith("IP="):
                                ip = parte.split("=")[1]
                                clave = f"Usuario: {usuario} (IP: {ip})"
                        conteo_fallos[clave] = conteo_fallos.get(clave, 0) + 1

            for objetivo, fallos in conteo_fallos.items():
                if fallos >= self._umbral:
                    alertas.append(f"[{self._nombre}] ¡Alerta! {objetivo} acumula {fallos} intentos fallidos (supera el umbral de {self._umbral}).")
        
        except FileNotFoundError:
            alertas.append(f"[{self._nombre}] Error: No se encontró el fichero {self._ruta_fichero}.")

        return alertas

class ComprobacionContrasenaDebil(Comprobacion):
    def __init__(self, nombre: str, ruta_fichero: str, usuarios_prueba: dict[str, str]):
        super().__init__(nombre)
        self._ruta_fichero = ruta_fichero
        self._usuarios_prueba = usuarios_prueba  # Diccionario {'usuario': 'contraseña'}

    def ejecutar(self) -> list[str]:
        alertas = []
        contraseñas_comunes = set()

        try:
            with open(self._ruta_fichero, 'r', encoding='utf-8') as f:
                for linea in f:
                    contraseñas_comunes.add(linea.strip())

            for usuario, password in self._usuarios_prueba.items():
                if password in contraseñas_comunes:
                    alertas.append(f"[{self._nombre}] ¡Alerta! El usuario '{usuario}' utiliza una contraseña muy débil o común ('{password}').")
        
        except FileNotFoundError:
            alertas.append(f"[{self._nombre}] Error: No se encontró el fichero de contraseñas {self._ruta_fichero}.")

        return alertas

class ComprobacionCabecerasWeb(Comprobacion):    
    def __init__(self, nombre: str, url: str):
        super().__init__(nombre)
        self._url = url
        self._cabeceras_requeridas = [
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]

    def ejecutar(self) -> list[str]:
        alertas = []
        try:
            respuesta = requests.get(self._url, timeout=5)
            cabeceras_recibidas = respuesta.headers

            faltantes = []
            for cabecera in self._cabeceras_requeridas:
                if cabecera not in cabeceras_recibidas:
                    faltantes.append(cabecera)

            if faltantes:
                alertas.append(f"[{self._nombre}] La URL '{self._url}' carece de las siguientes cabeceras de seguridad: {', '.join(faltantes)}.")
            else:
                alertas.append(f"[{self._nombre}] La URL '{self._url}' cumple con todas las cabeceras de seguridad evaluadas.")

        except requests.RequestException as e:
            alertas.append(f"[{self._nombre}] Error al conectar con la URL {self._url}: {e}")

        return alertas


class Auditor:    
    def __init__(self, comprobaciones: list[Comprobacion]):
        self._comprobaciones = comprobaciones

    def ejecutar_auditoria(self) -> dict[str, list[str]]:
        resultados = {}
        # Bucle único y plano, sin ningún "if" ni "isinstance". 
        # Cumple con el polimorfismo puro y permite añadir comprobaciones sin modificar el Auditor.
        for comp in self._comprobaciones:
            resultados[comp.nombre] = comp.ejecutar()
        
        return resultados