type Stage = "beta" | "prod";

interface MakePaymentProps {
  stage: Stage;
  apiKey: string;
  privateKey: string;
  body: Record<string, any>;
}

interface RequestData {
  httpMethod: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  queryStringParameters?: Record<string, string>;
  body?: Record<string, any>;
}

export class FinikWebClient {
  private headers: Record<string, string> | null = null;
  private stage: Stage = "beta";

  constructor(stage?: Stage) {
    if (stage) {
      this.stage = stage;
    }
  }

  // Generate UUID v4 using Web Crypto API (more secure and standard)
  private generateUUID(): string {
    // Modern browsers support crypto.randomUUID() - RFC 4122 compliant
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    
    // Fallback using crypto.getRandomValues for cryptographically secure random
    // This is RFC 4122 version 4 UUID compliant
    return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, (c: any) =>
      (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    );
  }

  private getBaseUrl(stage: Stage): string {
    const baseUrl =
      stage === "prod"
        ? "https://api.acquiring.averspay.kg"
        : "https://beta.api.acquiring.averspay.kg";

    return baseUrl;
  }

  private getHostFromUrl(url: string): string {
    const host = new URL(url).host;
    return host;
  }

  private prepareHeaders(apiKey: string, stage: Stage): Record<string, string> {
    const baseUrl = this.getBaseUrl(stage);
    const host = this.getHostFromUrl(baseUrl);
    const timestamp = Date.now().toString();

    const headers = {
      Host: host,
      "x-api-key": apiKey,
      "x-api-timestamp": timestamp,
    };

    this.headers = headers;
    return headers;
  }

  private prepareRequestData(input: MakePaymentProps): RequestData {
    const { apiKey, body, stage } = input;

    const paymentId = this.generateUUID();
    
    // Don't mutate original body - create new object
    const bodyWithId = {
      ...body,
      PaymentId: paymentId,
    };

    const requestData: RequestData = {
      httpMethod: "POST",
      path: "/v1/payment",
      headers: this.prepareHeaders(apiKey, stage),
      queryStringParameters: undefined,
      body: bodyWithId,
    };

    return requestData;
  }

  // === Signing methods ===
  
  protected getHttpMethod(requestData: RequestData): string {
    return requestData.httpMethod.toLowerCase();
  }

  protected getPath(requestData: RequestData): string {
    return decodeURI(requestData.path ?? '');
  }

  protected getHeadersData(requestData: RequestData): string {
    const { headers } = requestData;

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

  protected getQueryStringParamsData(requestData: RequestData): string {
    const queryParams = requestData.queryStringParameters ?? {};

    const sortedQueryParamKeys = Object.keys(queryParams).sort();

    const queryParamsData = sortedQueryParamKeys.map((key) => {
      const value = queryParams[key] ?? '';

      const queryParamData = encodeURI(decodeURI(key)) + '=' + encodeURI(decodeURI(value));

      return queryParamData;
    });

    return queryParamsData.join('&');
  }

  protected getJsonBody(requestData: RequestData): string {
    let body = '';

    if (requestData.body) {
      // sort object by key
      const sortedBody = Object.entries(requestData.body)
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

  protected getData(requestData: RequestData): string {
    const parts: string[] = [];

    const queryString = this.getQueryStringParamsData(requestData);

    parts.push(this.getHttpMethod(requestData));
    parts.push(this.getPath(requestData));
    parts.push(this.getHeadersData(requestData));

    if (queryString) {
      parts.push(queryString);
    }

    parts.push(this.getJsonBody(requestData));

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
      false,
      ['sign'],
    );

    return privateKey;
  }

  /**
   * Sign the request data using RSA-SHA256
   */
  private async sign(requestData: RequestData, privateKeyPem: string): Promise<string> {
    const privateKey = await this.importPrivateKey(privateKeyPem);

    const data = this.getData(requestData);

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
  async verify(publicKeyPem: string, signatureBase64: string, requestData: RequestData): Promise<boolean> {
    const publicKey = await this.importPublicKey(publicKeyPem);

    const data = this.getData(requestData);

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

  /**
   * Make a payment and get redirect URL
   */
  async makePayment(input: MakePaymentProps): Promise<string> {
    const { apiKey, privateKey, body, stage } = input;
    const requestData = this.prepareRequestData(input);

    const signature = await this.sign(requestData, privateKey);

    const url = `${this.getBaseUrl(stage)}${requestData.path}`;

    const res = await fetch(url, {
      method: requestData.httpMethod,
      headers: {
        ...this.prepareHeaders(apiKey, stage),
        "content-type": "application/json",
        signature,
      },
      body: JSON.stringify(requestData.body),
      redirect: "manual",
    });

    if (res.status === 302) {
      const paymentUrl = res.headers.get("location");

      console.log("paymentURL", paymentUrl);

      return paymentUrl || "error: no redirect location";
    } else {
      const errorText = await res.text();
      console.error(res.status, errorText);
      throw new Error(`Payment failed: ${res.status} - ${errorText}`);
    }
  }
}

// Extend Window interface for TypeScript
declare global {
  interface Window {
    FinikClient: typeof FinikWebClient;
  }
}

// Expose to window for CDN usage
if (typeof window !== "undefined") {
  window.FinikClient = FinikWebClient;
}

// Also export for module usage
export default FinikWebClient;

// Example usage:
/*
// In HTML with CDN:
<script src="https://cdn.jsdelivr.net/gh/arstan-ak/cdn-library@latest/index.js"></script>
<script>
  const client = new window.FinikClient('beta');
  
  client.makePayment({
    stage: 'beta',
    apiKey: 'your-api-key',
    privateKey: `-----BEGIN PRIVATE KEY-----
...your private key...
-----END PRIVATE KEY-----`,
    body: {
      amount: 100,
      currency: 'KGS',
      description: 'Test payment'
    }
  }).then(paymentUrl => {
    console.log('Redirect to:', paymentUrl);
    window.location.href = paymentUrl;
  }).catch(error => {
    console.error('Payment error:', error);
  });
</script>
*/