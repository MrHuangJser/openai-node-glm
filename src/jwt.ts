import CryptoJS from 'crypto-js';

interface Payload {
  [key: string]: any;
}

function base64url(source: CryptoJS.lib.WordArray): string {
  // Encode in classical base64
  let encodedSource = CryptoJS.enc.Base64.stringify(source);

  // Remove padding equal characters
  encodedSource = encodedSource.replace(/=+$/, '');

  // Replace characters according to base64url specifications
  encodedSource = encodedSource.replace(/\+/g, '-');
  encodedSource = encodedSource.replace(/\//g, '_');

  return encodedSource;
}

export function sign(payload: Payload, secret: string): string {
  // Create token header as a JSON string
  const header = {
    alg: 'HS256',
    sign_type: 'SIGN',
  };
  const stringifiedHeader = CryptoJS.enc.Utf8.parse(JSON.stringify(header));
  const encodedHeader = base64url(stringifiedHeader);

  // Create token payload as a JSON string
  const stringifiedPayload = CryptoJS.enc.Utf8.parse(JSON.stringify(payload));
  const encodedPayload = base64url(stringifiedPayload);

  // Create signature hash
  const token = encodedHeader + '.' + encodedPayload;
  const signature = CryptoJS.HmacSHA256(token, secret);
  const encodedSignature = base64url(signature);

  // Build and return the token
  return token + '.' + encodedSignature;
}
