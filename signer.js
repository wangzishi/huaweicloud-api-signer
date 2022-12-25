const ALGORITHM = "SDK-HMAC-SHA256";
const HEADER_X_DATE = "X-Sdk-Date";
const HEADER_AUTHORIZATION = "Authorization";
const HEADER_CONTENT_SHA256 = "x-sdk-content-sha256";
export class Signer {
    #key;
    #secret;
    #getTime() {
        const twoChar = (n) => (n > 10 ? n.toString() : `0${n}`);
        const date = new Date();
        const year = date.getUTCFullYear();
        const month = twoChar(date.getUTCMonth() + 1);
        const day = twoChar(date.getUTCDate());
        const hour = twoChar(date.getUTCHours());
        const minute = twoChar(date.getUTCMinutes());
        const second = twoChar(date.getUTCSeconds());
        return `${year}${month}${day}T${hour}${minute}${second}Z`;
    }
    #signedHeaders(headers) {
        const keys = [];
        headers.forEach((value, key) => {
            keys.push(key.toLowerCase());
        });
        return keys.sort();
    }
    #bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    }
    async #hexEncodeSHA256Hash(data) {
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashHex = this.#bufferToHex(hashBuffer);
        return hashHex;
    }
    #canonicalURL(request) {
        const url = new URL(request.url);
        return `${url.pathname}/`;
    }
    #canonicalQueryString(request) {
        const url = new URL(request.url);
        // TODO: 当 key 出现多次时，需要根据 value 排序，而不仅仅只是根据 key 排序
        url.searchParams.sort();
        return url.searchParams.toString();
    }
    #canonicalHeaders(request, signedHeaders) {
        const headers = [];
        for (const headerKey of signedHeaders) {
            const headerValue = request.headers.get(headerKey);
            headers.push(`${headerKey}:${headerValue?.trim()}`);
        }
        return headers.join("\n") + "\n";
    }
    async #canonicalRequest(request, signedHeaders) {
        let hexEncode = request.headers.get(HEADER_CONTENT_SHA256);
        if (hexEncode === null) {
            const data = await request.arrayBuffer();
            hexEncode = await this.#hexEncodeSHA256Hash(data);
        }
        // rome-ignore format:
        return (request.method + "\n" +
            this.#canonicalURL(request) + "\n" +
            this.#canonicalQueryString(request) + "\n" +
            this.#canonicalHeaders(request, signedHeaders) + "\n" +
            signedHeaders.join(";") + "\n" +
            hexEncode);
    }
    async #stringToSign(data, time) {
        const encoder = new TextEncoder();
        const hash = await this.#hexEncodeSHA256Hash(encoder.encode(data));
        return `${ALGORITHM}\n${time}\n${hash}`;
    }
    async #signStringToSign(stringToSign, signingKey) {
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", encoder.encode(signingKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const signBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(stringToSign));
        return this.#bufferToHex(signBuffer);
    }
    #authHeaderValue(signature, key, signedHeaders) {
        const signedHeadersString = signedHeaders.join(";");
        return `${ALGORITHM} Access=${key}, SignedHeaders=${signedHeadersString}, Signature=${signature}`;
    }
    constructor(key, secret) {
        this.#key = key;
        this.#secret = secret;
    }
    async sign(request) {
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
