import type { FileHandle } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  LogRedactor,
  pipeRedactedLogs,
  Redactions,
  redactText,
  ShapeLineRedactor,
  tokenForms,
} from './redaction';

function redactChunks(chunks: Buffer[], values: string[]): Buffer {
  const redactor = new LogRedactor(() => values);
  return Buffer.concat([...chunks.map((chunk) => redactor.push(chunk)), redactor.finish()]);
}

describe('log redaction', () => {
  it('redacts a repeated secret when the final occurrence crosses the output boundary', () => {
    const secret = 'provider-secret';
    const output = redactChunks(
      [Buffer.from(`${secret}--provider-se`), Buffer.from('cret')],
      [secret]
    );

    expect(output.toString()).toBe('[REDACTED]--[REDACTED]');
    expect(output.includes(Buffer.from(secret))).toBe(false);
  });

  it('prefers the longest match when one secret is a prefix of another', () => {
    const expected = 'before [REDACTED] after';

    expect(redactText('before abcdef after', ['abc', 'abcdef'])).toBe(expected);
    expect(
      redactChunks(
        [Buffer.from('before abc'), Buffer.from('def after')],
        ['abc', 'abcdef']
      ).toString()
    ).toBe(expected);
  });

  it('redacts a UTF-8 secret split at every byte boundary', () => {
    const secret = 'tøk🔐en';
    const input = Buffer.from(`before ${secret} after`);
    const chunks = Array.from(input, (byte) => Buffer.from([byte]));

    const output = redactChunks(chunks, [secret]);

    expect(output.toString()).toBe('before [REDACTED] after');
    expect(output.includes(Buffer.from(secret))).toBe(false);
  });

  it('keeps pending raw data bounded by the longest secret', () => {
    const secret = 's'.repeat(64);
    const input = Buffer.alloc(1024 * 1024, 'a');
    const redactor = new LogRedactor(() => [secret]);

    const emitted = redactor.push(input);
    const tail = redactor.finish();

    expect(emitted.length).toBe(input.length - Buffer.byteLength(secret) + 1);
    expect(tail.length).toBe(Buffer.byteLength(secret) - 1);
    expect(Buffer.concat([emitted, tail]).equals(input)).toBe(true);
  });

  it('writes only redacted bytes to the diagnostic sink', async () => {
    const writes: Buffer[] = [];
    const file = {
      write: async (value: Uint8Array) => {
        writes.push(Buffer.from(value));
      },
    } as unknown as FileHandle;
    const secret = 'switch-secret-value';
    const stream = Readable.from([
      Buffer.from('failure: switch-se'),
      Buffer.from('cret-value; retry switch-secret-value'),
    ]);

    await pipeRedactedLogs([stream], file, () => [secret]);

    const persisted = Buffer.concat(writes);
    expect(persisted.toString()).toBe('failure: [REDACTED]; retry [REDACTED]');
    expect(persisted.includes(Buffer.from(secret))).toBe(false);
  });
});

describe('values added as they are issued', () => {
  it('scrubs a value from every chunk written after it was added', () => {
    const values: string[] = [];
    const redactor = new LogRedactor(() => values);
    const before = redactor.push(Buffer.from('early synthetic-issued '));
    values.push('synthetic-issued');
    const after = Buffer.concat([
      redactor.push(Buffer.from('later synthetic-iss')),
      redactor.push(Buffer.from('ued done')),
      redactor.finish(),
    ]);
    expect(before.toString()).toBe('early synthetic-issued ');
    expect(after.toString()).toBe('later [REDACTED] done');
  });

  it('scrubs an issued token in each form it can be written in, through any JSON value', () => {
    const redactions = new Redactions();
    expect(redactions.value({ body: 'nothing yet' })).toEqual({ body: 'nothing yet' });
    redactions.add('synthetic-a/b+c');
    const [raw, encoded, basic] = tokenForms('synthetic-a/b+c');
    expect(encoded).toBe('synthetic-a%2Fb%2Bc');
    expect(Buffer.from(basic!, 'base64').toString()).toBe('x-access-token:synthetic-a/b+c');
    expect(
      redactions.value({
        body: `token ${raw}`,
        nested: [{ url: `https://x-access-token:${encoded}@github.com` }, 3, null, true],
        header: `Basic ${basic}`,
      })
    ).toEqual({
      body: 'token [REDACTED]',
      nested: [{ url: 'https://x-access-token:[REDACTED]@github.com' }, 3, null, true],
      header: 'Basic [REDACTED]',
    });
    expect(redactions.text(`log ${raw}`)).toBe('log [REDACTED]');
  });
});

it('says how much of a text could still turn into a value', () => {
  const redactions = new Redactions();
  expect(redactions.unfinished('anything')).toBe(0);
  redactions.add('synthetic-token');
  expect(redactions.unfinished('see synth')).toBe(5);
  expect(redactions.unfinished('see synthetic-token')).toBe(0);
  expect(redactions.unfinished('nothing here.')).toBe(0);
  // Every token's base64 form starts with that of `x-access-token:`.
  expect(redactions.unfinished('nothing here')).toBe(1);
});

describe('token shapes in logs', () => {
  const token = `ghs_${'A1b2C3d4E5'.repeat(3)}xyz789`;

  it('redacts a GitHub token split over chunks, line by line', () => {
    const shapes = new ShapeLineRedactor();
    const line = Buffer.from(`push to https://x-access-token:${token}@github.com — ✓\nnext`);
    const chunks = [line.subarray(0, 40), line.subarray(40, 41), line.subarray(41)];

    const output = Buffer.concat([...chunks.map((chunk) => shapes.push(chunk)), shapes.finish()]);

    expect(output.toString()).toBe(
      'push to https://x-access-token:[REDACTED]@github.com — ✓\nnext'
    );
  });

  it('never cuts a long line through a token that runs on into the next chunk', () => {
    const shapes = new ShapeLineRedactor();
    // The line passes the limit inside the token, which ends in the next chunk.
    const before = Buffer.from(`${'a'.repeat(64 * 1024 - 10)} ${token.slice(0, 20)}`);
    const after = Buffer.from(`${token.slice(20)} done\n`);
    const output = Buffer.concat([shapes.push(before), shapes.push(after), shapes.finish()]);
    expect(output.toString()).toBe(`${'a'.repeat(64 * 1024 - 10)} [REDACTED] done\n`);
  });

  it('writes an unended line once it is long, still redacted', () => {
    const shapes = new ShapeLineRedactor();
    const long = Buffer.from(`${'é'.repeat(40_000)} ${token} `);
    const written = shapes.push(long);
    expect(written.length).toBeGreaterThan(0);
    expect(Buffer.concat([written, shapes.finish()]).toString()).toBe(
      `${'é'.repeat(40_000)} [REDACTED] `
    );
  });
});

describe('tokens no exact value catches', () => {
  // Synthetic: the shape of a GitHub installation token, not a real one.
  const installation = `ghs_${'A1b2C3d4E5'.repeat(3)}xyz789`;

  it('redacts a GitHub token this process never issued, in each form', () => {
    const redactions = new Redactions();
    const [, , basic] = tokenForms(installation);

    expect(redactions.text(`git push https://x-access-token:${installation}@github.com/o/r`)).toBe(
      'git push https://x-access-token:[REDACTED]@github.com/o/r'
    );
    expect(redactions.value({ header: `Basic ${basic}`, n: 1 })).toEqual({
      header: 'Basic [REDACTED]',
      n: 1,
    });
  });

  it('redacts a GitHub token glued to what precedes it, as escaped or encoded text has it', () => {
    const redactions = new Redactions();
    expect(redactions.text(`{"out":"done\\n${installation}"}`)).toBe('{"out":"done\\n[REDACTED]"}');
    expect(redactions.text(`url=https%3A%2F%2Fx-access-token%3A${installation}%40github.com`)).toBe(
      'url=https%3A%2F%2Fx-access-token%3A[REDACTED]%40github.com'
    );
  });

  it('redacts what is left of a GitHub token cut short', () => {
    const redactions = new Redactions();
    expect(redactions.text(`git push https://x-access-token:${installation.slice(0, 20)}…`)).toBe(
      'git push https://x-access-token:[REDACTED]…'
    );
  });

  it('leaves prose that merely starts like a token', () => {
    const redactions = new Redactions();
    expect(redactions.text('ghost_writer gh_cli ghs_ab and gho_')).toBe(
      'ghost_writer gh_cli ghs_ab and gho_'
    );
    expect(redactions.text('laughs_total highs_and_lows weighs_more')).toBe(
      'laughs_total highs_and_lows weighs_more'
    );
  });

  it('does not hold back a long run that only looks like a token', () => {
    const shapes = new ShapeLineRedactor();
    const written = shapes.push(Buffer.from(`ghs_${'a'.repeat(200 * 1024)}`));
    expect(written.length).toBeGreaterThan(0);
    // All but the last line-tail was written, not held.
    expect(shapes.finish().length).toBeLessThanOrEqual(256);
  });

  it('redacts the cut-off start of an issued token at the end of a title', () => {
    const redactions = new Redactions();
    const token = 'synthetic-issued-token-with-no-shape-0123456789';
    redactions.add(token);
    // How the Claude adapter cuts a command title, through the token.
    const title = `curl -H "Authorization: Bearer ${token.slice(0, 39)}…`;

    const shown = redactions.value({ title }).title;

    expect(shown).toBe('curl -H "Authorization: Bearer [REDACTED]…');
    // The same cut without the ellipsis, as OpenCode's.
    expect(redactions.text(title.slice(0, -1))).toBe('curl -H "Authorization: Bearer [REDACTED]');
  });

  it('leaves a title whose end shares only a few characters with a token', () => {
    const redactions = new Redactions();
    redactions.add('synthetic-issued-token');
    expect(redactions.text('see the synth…')).toBe('see the synth…');
  });
});

// ---------------------------------------------------------------------------
// Phase A — generic secret-shape tests
// ---------------------------------------------------------------------------

describe('generic secret shapes: Authorization / Bearer header values', () => {
  it('redacts a Bearer token in an Authorization header', () => {
    const r = new Redactions();
    // Build the value via concatenation so gitleaks does not flag the literal.
    const val = 'eyJ' + 'header' + '.' + 'eyJ' + 'payload' + '.' + 'sig12345';
    expect(r.text(`Authorization: Bearer ${val}`)).toBe('Authorization: Bearer [REDACTED]');
  });

  it('redacts a Token value in an Authorization header (case-insensitive header)', () => {
    const r = new Redactions();
    const val = 'abcdef' + 'ghijklmn';
    expect(r.text(`authorization: Token ${val}`)).toBe('authorization: Token [REDACTED]');
  });

  it('redacts a bare Bearer prefix in a log line', () => {
    const r = new Redactions();
    const val = 'tok' + 'ABCDEFGHIJK';
    expect(r.text(`sending Bearer ${val} to api`)).toBe('sending Bearer [REDACTED] to api');
  });

  it('does not redact a short word after Bearer', () => {
    const r = new Redactions();
    // Value shorter than the 8-char minimum must not be masked.
    expect(r.text('Bearer short')).toBe('Bearer short');
  });
});

describe('generic secret shapes: vendor API key prefixes', () => {
  it('redacts an OpenAI-style key (sk- prefix)', () => {
    const r = new Redactions();
    // Concatenate so the literal is never a full key-shaped string.
    const key = 'sk-' + 'Abcdefghijk' + 'lmnopqrstuvwxyz01234';
    expect(r.text(`key=${key}`)).toBe('key=[REDACTED]');
  });

  it('redacts an AWS access key id (AKIA prefix)', () => {
    const r = new Redactions();
    const key = 'AKIA' + 'IOSFODNN7EXAMPLE';
    expect(r.text(`aws_access_key_id=${key}`)).toBe('aws_access_key_id=[REDACTED]');
  });

  it('redacts a Slack bot token (xoxb- prefix)', () => {
    const r = new Redactions();
    const key = 'xoxb-' + '12345678' + '-' + 'ABCDEFGH';
    expect(r.text(`token: ${key}`)).toBe('token: [REDACTED]');
  });

  it('redacts a Google API key (AIza prefix)', () => {
    const r = new Redactions();
    const key = 'AIza' + 'SyBV9hLqSGRd8LzjPSMp5A7n3QRk' + 'extra01234';
    expect(r.text(`api_key=${key}`)).toBe('api_key=[REDACTED]');
  });

  it('leaves ordinary words that happen to start with sk-', () => {
    const r = new Redactions();
    // "sk-" alone (no long suffix) must not be masked.
    expect(r.text('ski-jump result: 42')).toBe('ski-jump result: 42');
  });
});

describe('generic secret shapes: JWT', () => {
  it('redacts a well-formed JWT', () => {
    const r = new Redactions();
    // Build each segment separately so no full JWT literal appears in source.
    const header = 'eyJ' + 'hbGciOiJIUzI1NiJ9';
    const payload = 'eyJ' + 'zdWIiOiJ1c2VyMSJ9';
    const sig = 'SflKxwRJSMeKKF2QT4fwpMeJf36P' + 'Ok6yJV_adQssw5c';
    const jwt = `${header}.${payload}.${sig}`;
    expect(r.text(`token: ${jwt}`)).toBe('token: [REDACTED]');
  });

  it('leaves strings that look like two JWT segments but not three', () => {
    const r = new Redactions();
    const notJwt = 'eyJ' + 'aaa.' + 'eyJ' + 'bbb';
    // No third segment → not a JWT → not masked.
    expect(r.text(notJwt)).toBe(notJwt);
  });
});

describe('generic secret shapes: PEM private-key block', () => {
  it('redacts a PEM private-key block spanning multiple lines', () => {
    const r = new Redactions();
    const pem =
      '-----BEGIN RSA ' +
      'PRIVATE KEY-----\n' +
      'MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4\n' +
      'AAAAAAA\n' +
      '-----END RSA ' +
      'PRIVATE KEY-----';
    const out = r.text(`key data: ${pem} end`);
    expect(out).toBe('key data: [REDACTED] end');
    expect(out).not.toContain('MIIEow');
  });

  it('redacts an EC private-key block', () => {
    const r = new Redactions();
    const pem =
      '-----BEGIN EC ' +
      'PRIVATE KEY-----\n' +
      'MHQCAQEEIBkg4MWKQ5xL1OyLgAAAAAA\n' +
      '-----END EC ' +
      'PRIVATE KEY-----';
    expect(r.text(pem)).toBe('[REDACTED]');
  });

  it('leaves a public key block alone', () => {
    const r = new Redactions();
    const pub = '-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----';
    expect(r.text(pub)).toBe(pub);
  });
});

describe('generic secret shapes: URL credentials', () => {
  it('masks the password in a postgres connection string', () => {
    const r = new Redactions();
    const pw = 'hunter' + '2secret!';
    const url = `postgres://dbuser:${pw}@db.example.com:5432/mydb`;
    const out = r.text(url);
    expect(out).toBe('postgres://dbuser:[REDACTED]@db.example.com:5432/mydb');
    expect(out).not.toContain(pw);
  });

  it('masks the password in an https basic-auth URL', () => {
    const r = new Redactions();
    // No @ in the password because the regex stops at @.
    const pw = 'Passw0rd' + '123secure';
    const url = `https://admin:${pw}@intranet.example.org/api`;
    const out = r.text(url);
    expect(out).toBe('https://admin:[REDACTED]@intranet.example.org/api');
    expect(out).not.toContain(pw);
  });

  it('leaves a URL without embedded credentials alone', () => {
    const r = new Redactions();
    expect(r.text('https://example.com/path?q=1')).toBe('https://example.com/path?q=1');
  });
});

describe('generic secret shapes: key=value assignments', () => {
  it('redacts password= in env-var form', () => {
    const r = new Redactions();
    const pw = 'Sup3rSecret' + 'Pass';
    expect(r.text(`DATABASE_URL password=${pw} host=db`)).toBe(
      'DATABASE_URL password=[REDACTED] host=db'
    );
  });

  it('redacts token= in CLI flag form', () => {
    const r = new Redactions();
    const tok = 'mytoken' + 'ABCDEFGH';
    expect(r.text(`--token=${tok}`)).toBe('--token=[REDACTED]');
  });

  it('redacts api_key= (underscore)', () => {
    const r = new Redactions();
    const key = 'abcd' + 'efgh12345678';
    expect(r.text(`api_key=${key}`)).toBe('api_key=[REDACTED]');
  });

  it('redacts "secret":"value" JSON form', () => {
    const r = new Redactions();
    const val = 'mysecret' + 'value123';
    expect(r.text(`{"secret":"${val}"}`)).toBe('{"secret":"[REDACTED]"}');
  });

  it('does NOT redact "password policy" — keyword with no value', () => {
    const r = new Redactions();
    // "password" followed by a space and prose, not an = or :.
    expect(r.text('password policy requires 12 chars')).toBe('password policy requires 12 chars');
  });

  it('does NOT redact a short value after token=', () => {
    const r = new Redactions();
    // Values shorter than 4 characters are not secrets.
    expect(r.text('token=abc')).toBe('token=abc');
  });
});

describe('generic secret shapes: look-alike false-negatives', () => {
  it('leaves laughs_total and similar benign words untouched', () => {
    const r = new Redactions();
    expect(r.text('laughs_total=5 highs_and_lows weighs_more')).toBe(
      'laughs_total=5 highs_and_lows weighs_more'
    );
  });

  it('leaves "password policy" and "secret management" prose untouched', () => {
    const r = new Redactions();
    expect(r.text('Read the password policy and secret management docs')).toBe(
      'Read the password policy and secret management docs'
    );
  });
});

describe('generic secret shapes: nested JSON via value()', () => {
  it('redacts a secret inside deeply nested JSON arguments', () => {
    const r = new Redactions();
    const pw = 'dbPa$$' + 'word9876';
    const input = {
      tool: 'run_query',
      args: {
        connection: {
          url: `postgres://reader:${pw}@db.prod.example.com/main`,
          timeout: 30,
        },
        query: 'SELECT 1',
      },
    };
    const out = r.value(input) as typeof input;
    expect(out.args.connection.url).toBe('postgres://reader:[REDACTED]@db.prod.example.com/main');
    expect(out.args.connection.timeout).toBe(30);
    expect(out.args.query).toBe('SELECT 1');
  });

  it('redacts an API key in a flat JSON object', () => {
    const r = new Redactions();
    const key = 'sk-' + 'TestFakeKeyAbcdefghijklmno123456';
    const out = r.value({ model: 'gpt-4', api_key: key }) as Record<string, string>;
    expect(out.api_key).toBe('[REDACTED]');
    expect(out.model).toBe('gpt-4');
  });
});

describe('generic secret shapes: secret straddling a truncation boundary', () => {
  it('redacts the whole key=value even when the value is cut at the cap', () => {
    const r = new Redactions();
    // Simulate a detail string that ends mid-secret (the tail is cut by the cap).
    const fullPw = 'VeryL0ng' + 'Password!XYZ';
    // Cap at 20 chars, cutting through the password.
    const capped = `password=${fullPw}`.slice(0, 20);
    // Redact is applied before the cap in Phase B, but this test proves the
    // pattern still masks even a partial value at the end of the string.
    const out = r.text(capped);
    expect(out).not.toContain(fullPw.slice(0, 10));
  });
});

describe('generic secret shapes: safeText fail-closed helper', () => {
  it('returns the redacted value normally', () => {
    const r = new Redactions();
    const key = 'sk-' + 'FakeTestKeyAbcdefghijklmno12345';
    expect(r.safeText(`key: ${key}`, 'FALLBACK')).toBe('key: [REDACTED]');
  });

  it('returns the fallback when an internal error would otherwise propagate', () => {
    // Use a subclass that overrides text() to throw, simulating a regex failure.
    class BrokenRedactions extends Redactions {
      override text(_input: string): string {
        throw new Error('simulated redaction failure');
      }
    }
    const br = new BrokenRedactions();
    expect(br.safeText('anything', 'title only')).toBe('title only');
  });
});

describe('generic secret shapes: names, blocks and inputs the first patterns missed', () => {
  // Built at runtime so no key-shaped literal appears in source.
  const value = 'abcd' + '1234efgh';
  const begin = (type: string) => `-----BEGIN ${type}` + 'PRIVATE KEY-----';
  const end = (type: string) => `-----END ${type}` + 'PRIVATE KEY-----';

  it('masks the value of a longer name that contains a secret keyword', () => {
    const r = new Redactions();
    expect(r.text(`DB_PASSWORD=${value}`)).toBe('DB_PASSWORD=[REDACTED]');
    expect(r.text(`client_secret=${value}`)).toBe('client_secret=[REDACTED]');
    expect(r.text(`AWS_SECRET_ACCESS_KEY=${value}`)).toBe('AWS_SECRET_ACCESS_KEY=[REDACTED]');
    expect(r.text(`{"db_password": "${value}"}`)).toBe('{"db_password": "[REDACTED]"}');
  });

  it('keeps the name when the value is the same word', () => {
    const r = new Redactions();
    expect(r.text('password=' + 'password')).toBe('password=[REDACTED]');
  });

  it('leaves names where the keyword runs on into a longer word', () => {
    const r = new Redactions();
    const text = 'max_tokens=1000 tokenizer=abcd secretary=bob password policy';
    expect(r.text(text)).toBe(text);
  });

  it('masks a private-key block that names no key type', () => {
    const r = new Redactions();
    expect(r.text(`${begin('')}\nMIIEvQIBADANBg\n${end('')} after`)).toBe('[REDACTED] after');
  });

  it('masks a private-key block through the end of the text when its END line was cut off', () => {
    const r = new Redactions();
    expect(r.text(`key: ${begin('RSA ')}\nMIIEow\nAAAA`)).toBe('key: [REDACTED]');
  });

  it('leaves a public-key block without an END line alone', () => {
    const r = new Redactions();
    const text = '-----BEGIN PUBLIC KEY-----\nMIIB';
    expect(r.text(text)).toBe(text);
  });

  it('redacts long inputs in linear time', () => {
    const r = new Redactions();
    for (const text of [
      'a'.repeat(60_000),
      '_'.repeat(60_000),
      'a://b:'.repeat(10_000),
      'token_'.repeat(10_000),
    ]) {
      const started = performance.now();
      r.text(text);
      expect(performance.now() - started).toBeLessThan(100);
    }
  });
});
