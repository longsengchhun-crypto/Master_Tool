import { inject } from 'vitest';

// Same secrets as the server under test, so the tests can seal TOTP seeds and compute HMACs the server will accept.
const s = inject('secrets');
process.env.SESSION_SECRET = s.SESSION_SECRET;
process.env.DEVICE_TOKEN_PEPPER = s.DEVICE_TOKEN_PEPPER;
