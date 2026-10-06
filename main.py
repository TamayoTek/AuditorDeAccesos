from comprobaciones import (
    Auditor,
    ComprobacionCabecerasWeb,
    ComprobacionIntentosFallidos,
    ComprobacionContrasenaDebil
)

def main():
    print("Iniciando auditoria de seguridad...")

    usuarios_prueba = {
        "usuario1": "123456",
        "usuario2": "password",
        "usuario3": "segura123"
    }

    comp_intentos = ComprobacionIntentosFallidos("Auditoría de Logs de Acceso", umbral=3)
    comp_pass = ComprobacionContrasenaDebil("Auditoría de Contraseñas Débiles", usuarios_prueba)

    comp_intentos = ComprobacionIntentosFallidos("Auditoría de Logs de Acceso", umbral=3)
    comp_pass = ComprobacionContrasenaDebil("Auditoría de Contraseñas Débiles", usuarios_prueba)
    
    comp_web_example = ComprobacionCabecerasWeb("Auditoría Cabeceras (Example)")
    comp_web_github = ComprobacionCabecerasWeb("Auditoría Cabeceras (GitHub)")

    auditor = Auditor([comp_intentos, comp_pass])

    objetivos_locales = {
        "log": "Recursos/sample_intentos_acceso.log",
        "diccionario": "Recursos/contrasenas_comunes.txt"
    }

    resultados = auditor.ejecutar_auditoria(objetivos_locales)
    for nombre_comp, alertas in resultados.items():
        print(f"\n--- {nombre_comp} ---")
        for alerta in alertas:
            print(f"  * {alerta}")

    print(f"\n--- {comp_web_example.nombre} ---")
    for alerta in comp_web_example.ejecutar("https://example.com"):
        print(f"  * {alerta}")

    print(f"\n--- {comp_web_github.nombre} ---")
    for alerta in comp_web_github.ejecutar("https://github.com"):
        print(f"  * {alerta}")

    print("\n--- AUDITORÍA FINALIZADA ---")

if __name__ == "__main__":
    main()