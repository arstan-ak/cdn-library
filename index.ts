interface RequestData {
  httpMethod: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  queryStringParameters?: Record<string, string>;
  body?: Record<string, any>;
}

export class FinikWebClient {
  private requestData: RequestData;

  constructor(requestData: RequestData) {
    console.log('request data:', requestData);
    this.requestData = requestData;
  }

  protected getHttpMethod(): string {
    return this.requestData.httpMethod.toLowerCase();
  }

  protected getPath(): string {
    return decodeURI(this.requestData.path ?? '');
  }

  protected getHeadersData(): string {
    const { headers } = this.requestData;

    const Host = headers.Host || headers.host;

    if (!Host) {
      throw new Error(`Header 'Host' is required`);
    }

    const headerData = `host:${Host.toString()}`;

    const sortedHeadersKeys = Object.keys(headers)
      .filter((key) => key.toLowerCase().startsWith('x-api-'))
      .sort();

    const headersData = sortedHeadersKeys.map((key) => {
      const value = headers[key];

      if (typeof value === 'undefined' || value === null || typeof value.toString !== 'function') {
        throw new Error(`Header '${key}' contains invalid value`);
      }

      const headerData = key.toLowerCase() + ':' + value.toString();

      return headerData;
    });

    return [headerData, ...headersData].join('&');
  }

  protected getQueryStringParamsData(): string {
    const queryParams = this.requestData.queryStringParameters ?? {};

    const sortedQueryParamKeys = Object.keys(queryParams).sort();

    const queryParamsData = sortedQueryParamKeys.map((key) => {
      const value = queryParams[key] ?? '';

      const queryParamData = encodeURI(decodeURI(key)) + '=' + encodeURI(decodeURI(value));

      return queryParamData;
    });

    return queryParamsData.join('&');
  }

  protected getJsonBody(): string {
    let body = '';

    if (this.requestData.body) {
      // sort object by key
      const sortedBody = Object.entries(this.requestData.body)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .reduce(
          (result, [key, value]) => {
            result[key] = value;
            return result;
          },
          {} as Record<string, any>,
        );

      body = JSON.stringify(sortedBody);
    }

    return body;
  }

  protected getData(): string {
    const parts: string[] = [];

    const queryString = this.getQueryStringParamsData();

    parts.push(this.getHttpMethod());
    parts.push(this.getPath());
    parts.push(this.getHeadersData());

    if (queryString) {
      parts.push(queryString);
    }

    parts.push(this.getJsonBody());

    return parts.join('\n');
  }

  /**
   * Import RSA private key from PEM format
   */
  private async importPrivateKey(pemKey: string): Promise<CryptoKey> {
    // Remove PEM headers and whitespace
    const pemContents = pemKey
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace('-----BEGIN RSA PRIVATE KEY-----', '')
      .replace('-----END RSA PRIVATE KEY-----', '')
      .replace(/\s/g, '');

    // Decode base64 to binary
    const binaryKey = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));

    // Import key into Web Crypto API
    const privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      binaryKey,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false, // not extractable for security
      ['sign'],
    );

    return privateKey;
  }

  /**
   * Sign the request data using RSA-SHA256
   */
  async sign(privateKeyPem: string): Promise<string> {
    const privateKey = await this.importPrivateKey(privateKeyPem);

    const data = this.getData();

    console.log('Data to be signed:', data);

    // Convert string to bytes
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(data);

    // Sign the data
    const signatureBuffer = await window.crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, dataBytes);

    // Convert signature to base64
    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    const signatureBase64 = btoa(String.fromCharCode(...signatureArray));

    return signatureBase64;
  }

  /**
   * Import RSA public key from PEM format
   */
  private async importPublicKey(pemKey: string): Promise<CryptoKey> {
    // Remove PEM headers and whitespace
    const pemContents = pemKey
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace('-----BEGIN RSA PUBLIC KEY-----', '')
      .replace('-----END RSA PUBLIC KEY-----', '')
      .replace(/\s/g, '');

    // Decode base64 to binary
    const binaryKey = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));

    // Import key into Web Crypto API
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      binaryKey,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['verify'],
    );

    return publicKey;
  }

  /**
   * Verify the signature using RSA-SHA256
   */
  async verify(publicKeyPem: string, signatureBase64: string): Promise<boolean> {
    const publicKey = await this.importPublicKey(publicKeyPem);

    const data = this.getData();

    console.log('Data to be verified:', data);

    // Convert string to bytes
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(data);

    // Convert base64 signature to bytes
    const signatureString = atob(signatureBase64);
    const signatureBytes = Uint8Array.from(signatureString, (c) => c.charCodeAt(0));

    // Verify the signature
    const isValid = await window.crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signatureBytes, dataBytes);

    return isValid;
  }
}

