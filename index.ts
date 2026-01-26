/* External dependencies */
import { v4 as uuid } from "uuid";
import { Signer } from "./signer";

type Stage = "beta" | "prod";

interface MakePaymentProps {
  stage: Stage;
  apiKey: string;
  privateKey: string;
  body: object;
}

export class FinikWebClient {
  private headers: any;

  getBaseUrl(): string {
    const baseUrl =
      undefined === "prod"
        ? "https://api.acquiring.averspay.kg"
        : "https://beta.api.acquiring.averspay.kg";

    return baseUrl;
  }

  private getHostFromUrl(url: string) {
    const host = new URL(url).host;

    return host;
  }

  prepareHeaders(apiKey: string) {
    const baseUrl = this.getBaseUrl();
    const host = this.getHostFromUrl(baseUrl);
    const timestamp = Date.now().toString();

    const headers = {
      Host: host,
      "x-api-key": apiKey,
      "x-api-timestamp": timestamp,
    };

    if (!this.headers) {
      this.headers = headers;
    }

    return this.headers;
  }

  private prepareRequestData(input: MakePaymentProps) {
    const { apiKey, body } = input;

    const paymentId = uuid();
    body["PaymentId"] = paymentId;

    const requestData = {
      httpMethod: "POST",
      path: "/v1/payment",
      headers: this.prepareHeaders(apiKey),
      queryStringParameters: undefined,
      body: body,
    };

    return requestData;
  }

  private async generateSignature(requestData: any, privateKey: string) {
    const signature = await new Signer(requestData).sign(privateKey);

    return signature;
  }

  async makePayment(input: MakePaymentProps) {
    const { apiKey, privateKey, body } = input;
    const requestData = this.prepareRequestData(input);

    const signature = await this.generateSignature(requestData, privateKey);

    const url = `${this.getBaseUrl()}${requestData.path}`;

    const res = await fetch(url, {
      method: requestData.httpMethod,
      headers: {
        ...this.prepareHeaders(apiKey),
        "content-type": "application/json",
        signature,
      },
      body: JSON.stringify(body),
      redirect: "manual",
    });

    if (res.status === 302) {
      // Read Location when you opt into redirects
      const paymentUrl = res.headers.get("location");

      console.log("paymentURL", paymentUrl);

      return paymentUrl;
    } else {
      console.error(res.status, await res.text());
      return "error caused";
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
