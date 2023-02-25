const doPost = (request = {}) => {
  const { parameter, postData: { contents, type } = {} } = request;
  const { source } = parameter;

  if (type === 'application/json') {
    const jsonData = JSON.parse(contents);
    var totp = jsonData.totp;

    // Verificar que el valor ingresado en totp sea un número entero de 6 dígitos
    var isValidTOTP = /^\d{6}$/.test(totp);
    if (!isValidTOTP) {
      return 'ERR: TOTP invalid';
    }
    
    // Llamar a la función verifyTOTP para verificar el TOTP
    var key = "JBSWY3DPEHPK3PXP";
    var result = verifyTOTP(key, totp);

    if (result) {
      // El TOTP es válido
      return ContentService.createTextOutput('Success');
    } else {
      // El TOTP no es válido
      return ContentService.createTextOutput('ERR: TOTP invalid')
    }
  }

  return ContentService.createTextOutput(contents);
};

function testOTP() {
  const key = "JBSWY3DPEHPK3PXP"; // clave secreta en formato base64
  const timeStep = 30; // intervalo de tiempo de 30 segundos
  const digits = 6; // cantidad de dígitos en el código TOTP

  // Generar un código TOTP
  const totp = generateTOTP(key, timeStep, digits);
  Logger.log("Código TOTP generado: " + totp);

  // Verificar un código TOTP
  const codeToVerify = "532254"; // código TOTP a verificar
  const isVerified = verifyTOTP(key, codeToVerify, timeStep, 1);
  if (isVerified) {
    Logger.log("El código TOTP es válido.");
  } else {
    Logger.log("El código TOTP no es válido.");
  }
}


function base32tohex(base32) {
  // Establecer una constante para almacenar los caracteres base32 y hexadecimales
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const hexChars = "0123456789abcdef";

  // Inicializar las variables bits y hex
  let bits = "";
  let hex = "";

  // Iterar sobre cada caracter del número en formato base32
  for (let i = 0; i < base32.length; i++) {
    // Encontrar la posición del caracter en la cadena de caracteres base32 y agregarlo a la cadena bits
    const val = base32chars.indexOf(base32[i].toUpperCase());
    bits += val.toString(2).padStart(5, "0");
  }

  // Iterar sobre cada grupo de 4 bits en la cadena bits
  for (let i = 0; i < bits.length; i += 4) {
    // Extraer un grupo de 4 bits de la cadena bits y convertirlo en un número decimal
    const chunk = bits.substr(i, 4);
    const decimal = parseInt(chunk, 2);

    // Agregar el equivalente hexadecimal del número decimal a la cadena hex
    hex += hexChars[decimal];
  }

  // Devolver el número hexadecimal resultante
  return hex;
}

function generateTOTP(secret, timeStepSeconds = 30, digits = 6) {
  // Convierte el secreto de base32 a hexadecimal.
  var str = base32tohex(secret);

  // Crea un arreglo de bytes a partir del string hexadecimal.
  const bytes = new Uint8Array(str.length / 2);
  for (let i = 0; i < str.length; i += 2) {
    bytes[i / 2] = parseInt(str.substr(i, 2), 16);
  }

  // Obtiene el timestamp actual en segundos.
  const timestamp = Math.floor(Date.now() / 1000);

  // Calcula el valor del contador en base al timestamp y al intervalo de tiempo.
  var counter = Math.floor(timestamp / timeStepSeconds);

  // Crea un arreglo de bytes a partir del valor del contador.
  const counterBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = counter & 0xff;
    counter >>>= 8;
  }

  // Calcula el valor HMAC-SHA1 del contador y el secreto.
  const hmacDigest = Utilities.computeHmacSignature(Utilities.MacAlgorithm.HMAC_SHA_1, counterBytes, bytes);

  // Calcula el valor de desplazamiento para el truncamiento.
  const offset = hmacDigest[hmacDigest.length - 1] & 0xf;

  // Trunca el valor HMAC-SHA1 y lo convierte en un número de la longitud especificada.
  const truncatedHash = (
    ((hmacDigest[offset] & 0x7f) << 24) |
    ((hmacDigest[offset + 1] & 0xff) << 16) |
    ((hmacDigest[offset + 2] & 0xff) << 8) |
    (hmacDigest[offset + 3] & 0xff)
  ) % Math.pow(10, digits);

  // Devuelve el valor truncado como un string, rellenando con ceros si es necesario.
  return truncatedHash.toString().padStart(digits, '0');
}

function verifyTOTP(key, totp, timeStep = 30, windowSize = 1) {
  // Recorre un rango de valores que abarca la ventana de tiempo permitida.
  for (let i = -windowSize; i <= windowSize; i++) {
    // Genera el TOTP esperado para el valor de tiempo actual.
    const expectedTOTP = generateTOTP(key, timeStep, totp.length);
    
    // Compara el TOTP esperado con el TOTP proporcionado.
    if (expectedTOTP === totp) {
      // Si coinciden, devuelve verdadero.
      return true;
    }
  }
  
  // Si no se encontró coincidencia, devuelve falso.
  return false;
}
