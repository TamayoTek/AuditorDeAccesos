from comprobaciones import (
    ComprobacionIntentosFallidos
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

if __name__ == "__main__":
    main()