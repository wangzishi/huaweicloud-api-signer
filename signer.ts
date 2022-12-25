const ALGORITHM = "SDK-HMAC-SHA256";
const HEADER_X_DATE = "X-Sdk-Date";
const HEADER_AUTHORIZATION = "Authorization";
const HEADER_CONTENT_SHA256 = "x-sdk-content-sha256";

export class Signer {
  #key: string;
  #secret: string;

  #getTime() {
    const twoChar = (n: number) => (n > 10 ? n.toString() : `0${n}`);
    const date = new Date();
    const year = date.getUTCFullYear();
    const month = twoChar(date.getUTCMonth() + 1);
    const day = twoChar(date.getUTCDate());
    const hour = twoChar(date.getUTCHours());
    const minute = twoChar(date.getUTCMinutes());
    const second = twoChar(date.getUTCSeconds());

    return `${year}${month}${day}T${hour}${minute}${second}Z`;
  }

  #signedHeaders(headers: Headers): string[] {
    const keys: string[] = [];
    headers.forEach((value, key) => {
      keys.push(key.toLowerCase());
    });

    return keys.sort();
  }

  #bufferToHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async #hexEncodeSHA256Hash(data: ArrayBuffer): Promise<string> {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashHex = this.#bufferToHex(hashBuffer);

    return hashHex;
  }

  #canonicalURL(request: Request): string {
    const url = new URL(request.url);
    return `${url.pathname}/`;
  }

  #canonicalQueryString(request: Request): string {
    const url = new URL(request.url);
    // TODO: 当 key 出现多次时，需要根据 value 排序，而不仅仅只是根据 key 排序
    url.searchParams.sort();
    return url.searchParams.toString();
  }

  #canonicalHeaders(request: Request, signedHeaders: string[]) {
    const headers: string[] = [];
    for (const headerKey of signedHeaders) {
      const headerValue = request.headers.get(headerKey);

      headers.push(`${headerKey}:${headerValue?.trim()}`);
    }

    return headers.join("\n") + "\n";
  }

  async #canonicalRequest(request: Request, signedHeaders: string[]): Promise<string> {
    let hexEncode = request.headers.get(HEADER_CONTENT_SHA256);
    if (hexEncode === null) {
      const data = await request.arrayBuffer();
      hexEncode = await this.#hexEncodeSHA256Hash(data);
    }

    // rome-ignore format:
    return (
      request.method 								 + "\n" +
      this.#canonicalURL(request)                    + "\n" +
      this.#canonicalQueryString(request)            + "\n" +
      this.#canonicalHeaders(request, signedHeaders) + "\n" +
      signedHeaders.join(";")                        + "\n" +
      hexEncode
    );
  }

  async #stringToSign(data: string, time: string) {
    const encoder = new TextEncoder();
    const hash = await this.#hexEncodeSHA256Hash(encoder.encode(data));

    return `${ALGORITHM}\n${time}\n${hash}`;
  }

  async #signStringToSign(stringToSign: string, signingKey: string) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(signingKey),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    const signBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(stringToSign));

    return this.#bufferToHex(signBuffer);
  }

  #authHeaderValue(signature: string, key: string, signedHeaders: string[]): string {
    const signedHeadersString = signedHeaders.join(";");
    return `${ALGORITHM} Access=${key}, SignedHeaders=${signedHeadersString}, Signature=${signature}`;
  }

  constructor(key: string, secret: string) {
    this.#key = key;
    this.#secret = secret;
  }

  async sign(request: Request) {
    let headerTime = request.headers.get(HEADER_X_DATE);

    if (headerTime === null) {
      headerTime = this.#getTime();
      request.headers.set(HEADER_X_DATE, headerTime);
    }

    const signedHeaders = this.#signedHeaders(request.headers);
    const canonicalRequest = await this.#canonicalRequest(request, signedHeaders);
    const stringToSign = await this.#stringToSign(canonicalRequest, headerTime);
    const signature = await this.#signStringToSign(stringToSign, this.#secret);

    request.headers.set(HEADER_AUTHORIZATION, this.#authHeaderValue(signature, this.#key, signedHeaders));

    console.log(request);
  }
}
