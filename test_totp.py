import os
import json
import hmac
import time
import base64
import struct
import requests

def generate_key():
    # generar clave secreta aleatoria
    secret_key = base64.b32encode(os.urandom(10)).decode()

    return secret_key

def generate_totp(key, time_step=30, digits=6):
    hmac_algorithm = "sha1" # algoritmo HMAC
    unix_time = int(time.time()) # timestamp actual
    time_counter = unix_time // time_step # contador de tiempo
    time_buffer = struct.pack(">Q", time_counter) # contador empaquetado en el formato de byte ">Q"
    
    # Decodificamos la clave base32 en un formato de bytes
    hmac_key = base64.b32decode(key, casefold=True)
    # Generamos la firma HMAC utilizando la clave y el contador de tiempo empaquetado
    hmac_signature = hmac.new(hmac_key, time_buffer, hmac_algorithm).digest()
    # Tomamos el último byte de la firma y aplicamos una máscara para obtener el offset
    offset = hmac_signature[-1] & 0xf
    # Tomamos 4 bytes de la firma a partir del offset y los empaquetamos en un formato de byte especificado por ">I"
    code = struct.unpack(">I", hmac_signature[offset : offset + 4])[0] & 0x7fffffff
    # Tomamos los últimos dígitos del código generado y los rellenamos con ceros a la izquierda si es necesario
    totp = str(code % 10 ** digits).zfill(digits)

    return totp

def verify_totp(key, totp, time_step=30, window_size=1):
    # Iteramos a través de una ventana de tiempo, que cubre el tiempo actual más y menos el tamaño de la ventana
    for i in range(-window_size, window_size + 1):
        # Generamos el código TOTP esperado para el intervalo de tiempo actual
        expected_totp = generate_totp(key, time_step, len(totp))
        # Comparamos el código TOTP generado con el código TOTP proporcionado
        if expected_totp == totp:
            # Si los códigos coinciden, devolvemos True
            return True
    # Si no se encuentra un código TOTP válido en la ventana de tiempo, devolvemos False
    return False

def send_totp(totp):
    # Crear el objeto JSON con el valor TOTP
    data = {'totp': totp}
    
    # Enviar la solicitud POST al servidor de Google Apps Script
    response = requests.post(url, data=json.dumps(data), headers=headers)
    
    # Manejar la respuesta del servidor de Google Apps Script
    if response.status_code == 200:
        return response.text

if __name__ == "__main__":
    key = "JBSWY3DPEHPK3PXP" # clave secreta en formato base32
    time_step = 30 # intervalo de tiempo de 30 segundos
    digits = 6 # cantidad de dígitos en el código TOTP

    # Definir la URL del servidor de Google Apps Script
    url = 'https://script.google.com/macros/s/AKfycbzePQNv9yovylt1AZB0754SIp9JAKce8XDSNlyuPG9vpBXfK6AOx6zjhI3Bsxm0Pn6-/exec'
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    # Generar un código TOTP
    totp = generate_totp(key, time_step, digits)
    print("Código TOTP generado:", totp)

    #Enviamos TOTP a Google Apps Script
    print ("Respuesta Google Apps Script:", send_totp(totp))
