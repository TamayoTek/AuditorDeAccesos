from comprobaciones import (
    Auditor,
    ComprobacionCabecerasWeb,
    ComprobacionIntentosFallidos,
    ComprobacionContrasenaDebil
)

def main():
    print("Iniciando auditoria de seguridad...\n")

    usuarios_prueba = {
        "usuario1": "123456",
        "usuario2": "password",
        "usuario3": "segura123"
    }

    # Instanciación pasando cada objeto su propio recurso o URL de forma encapsulada
    comp_intentos = ComprobacionIntentosFallidos(
        "Auditoría de Logs de Acceso", 
        "Recursos/sample_intentos_acceso.log", 
        umbral=3
    )
    
    comp_pass = ComprobacionContrasenaDebil(
        "Auditoría de Contraseñas Débiles", 
        "Recursos/contrasenas_comunes.txt", 
        usuarios_prueba
    )
    
    comp_web_example = ComprobacionCabecerasWeb(
        "Auditoría Cabeceras (Example)", 
        "https://example.com"
    )
    
    comp_web_github = ComprobacionCabecerasWeb(
        "Auditoría Cabeceras (GitHub)", 
        "https://github.com"
    )

    # Todas las comprobaciones se agrupan y se tratan uniformemente
    auditor = Auditor([
        comp_intentos, 
        comp_pass, 
        comp_web_example, 
        comp_web_github
    ])

    resultados = auditor.ejecutar_auditoria()
    
    for nombre_comp, alertas in resultados.items():
        print(f"--- {nombre_comp} ---")
        for alerta in alertas:
            print(f"  * {alerta}")
        print()

    print("--- AUDITORÍA FINALIZADA ---")

if __name__ == "__main__":
    main()