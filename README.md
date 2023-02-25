# TOTP-GoogleAppsScript

Este proyecto se basa en Google Apps Script, una plataforma de desarrollo basada en JavaScript que permite crear aplicaciones personalizadas y automatizar tareas dentro de los productos de Google. En particular, este proyecto utiliza Google Apps Script para crear una función que genera un código TOTP (Time-based One-Time Password) para la autenticación de dos factores. Este código se genera utilizando una clave secreta compartida entre el usuario y el proveedor de servicios, y se basa en un algoritmo criptográfico que cambia cada cierto tiempo.

## Ejemplo

Para probar el funcionamiento del Web App podemos utilizar *test_totp.py*:

<pre><font color="#5FD700">❯</font> python3 test_totp.py
Código TOTP generado: 897364
Respuesta Google Apps Script: Success</pre>

Para generar una nueva clave secreta:

```python3
secret_key = base64.b32encode(os.urandom(10)).decode() # 74PABE337AWN4EWO
```
