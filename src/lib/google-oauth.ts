import {
  decodeProtectedHeader,
  importPKCS8,
  importX509,
  JWTPayload,
  jwtVerify,
  SignJWT,
} from 'jose';

import type { Cache } from './cache/cache';

/**
 * Get an OAuth 2.0 token from google authentication apis using
 * a service account
 * @param serviceAccountEmail Email of the service account
 * @param privateKey Private key of the service account
 * @param scope scope to request
 * @returns OAuth 2.0 token
 */
export async function getAuthToken(
  serviceAccountEmail: string,
  privateKey: string,
  scope: string
): Promise<string> {
  const ecPrivateKey = await importPKCS8(privateKey, 'RS256');

  const jwt = await new SignJWT({ scope: scope })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(serviceAccountEmail)
    .setAudience('https://oauth2.googleapis.com/token')
    .setExpirationTime('1h')
    .setIssuedAt()
    .sign(ecPrivateKey);

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cache-Control': 'no-cache',
      Host: 'oauth2.googleapis.com',
    },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  const oauth = await response.json();
  return oauth.access_token;
}

async function getTtl(url: string) {
	const response = await fetch(url);

	// Step 2: Check and parse Cache-Control header
	const cacheControl = response.headers.get('Cache-Control');
	if (cacheControl) {
		const directives = cacheControl.split(',').map((d) => d.trim());
		const maxAgeDirective = directives.find((d) => d.startsWith('max-age='));

		if (maxAgeDirective) {
			const maxAge = parseInt(maxAgeDirective.split('=')[1], 10);
			return { maxAge, response };
		} else {
			return { maxAge: 0, response };
		}
	} else {
		return { magAge: 0, response };
	}
}

/**
 * Verifies an Identity Platform ID token.
 * If the token is valid, the promise is fulfilled with the token's decoded claims; otherwise, the promise is rejected.
 * @param idToken An Identity Platform ID token
 */
export async function verifyIdToken(idToken: string, cache: Cache | undefined = undefined): Promise<JWTPayload> {
  let data: any;
	const url =
		'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

	if (cache) {
		const key = 'google-public-keys';

		try {
			const cachedValue = await cache.get(key);
			data = cachedValue ? JSON.parse(cachedValue as string) : undefined;

			if (!data) {
				const { maxAge, response } = await getTtl(url);
				data = await response.json();

				await cache.put(key, JSON.stringify(data), {
					expirationTtl: maxAge
				});
			}
		} catch (error) {
			console.error(error);

			const res = await fetch(url);
			data = await res.json();
		}
	} else {
		const res = await fetch(url);
		data = await res.json();
	}

  //Get the correct publicKey from the key id
  const header = decodeProtectedHeader(idToken);
  const certificate = data[header.kid];
  const publicKey = await importX509(certificate, 'RS256');

  //Verify JWT with public key
  const { payload } = await jwtVerify(idToken, publicKey);
  return payload;
}
