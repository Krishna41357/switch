import type { FileHandle } from 'node:fs/promises';
import type { Readable } from 'node:stream';

/**
 * Exact-value redaction of secrets: what a host scrubs from the logs, journals
 * and messages it writes. The service tokens a session is given are added as
 * they are issued, so whatever redacts reads the values it holds at that
 * moment.
 */

const REDACTED = Buffer.from('[REDACTED]');

function secretBuffers(values: readonly string[]): Buffer[] {
  return [...new Set(values.filter(Boolean))]
    .map((value) => Buffer.from(value))
    .sort((left, right) => right.length - left.length);
}

function matchAt(input: Buffer, offset: number, secrets: readonly Buffer[]): Buffer | undefined {
  return secrets.find(
    (secret) =>
      offset + secret.length <= input.length &&
      input.subarray(offset, offset + secret.length).equals(secret)
  );
}

function redactPrefix(
  input: Buffer,
  scanLimit: number,
  secrets: readonly Buffer[]
): { output: Buffer; consumed: number } {
  const parts: Buffer[] = [];
  let literalStart = 0;
  let cursor = 0;
  while (cursor < scanLimit) {
    const secret = matchAt(input, cursor, secrets);
    if (!secret) {
      cursor += 1;
      continue;
    }
    if (literalStart < cursor) parts.push(input.subarray(literalStart, cursor));
    parts.push(REDACTED);
    cursor += secret.length;
    literalStart = cursor;
  }
  if (!parts.length) return { output: input.subarray(0, cursor), consumed: cursor };
  if (literalStart < cursor) parts.push(input.subarray(literalStart, cursor));
  return { output: Buffer.concat(parts), consumed: cursor };
}

/** Exact-value redaction that prefers the longest value when secrets overlap. */
export function redactText(text: string, values: readonly string[]): string {
  const secrets = secretBuffers(values);
  if (!secrets.length) return text;
  return redactPrefix(Buffer.from(text), Buffer.byteLength(text), secrets).output.toString();
}

/**
 * The forms an issued token can be written in: as it is, URL-encoded, and as
 * the base64 of `x-access-token:<token>`, which is how Git sends GitHub's
 * in an `Authorization` header (and so how a Git trace shows it).
 */
export function tokenForms(token: string): string[] {
  return [
    token,
    encodeURIComponent(token),
    Buffer.from(`x-access-token:${token}`).toString('base64'),
  ];
}

/**
 * GitHub's token shapes, matched whether or not this process issued the token:
 * one a sibling session fetched, or fetched before this session resumed or its
 * host restarted, or cut short in a title, all of which an exact value misses.
 * At a word boundary, four characters after the prefix tell a cut token from
 * prose. Glued to what precedes it, as escaped or encoded text has a token
 * (`\nghs_…` in JSON, `%3Aghs_…` in a URL), only a whole one counts, so a word
 * that merely contains a prefix (`laughs_total`, `highs_`) is left alone.
 */
const TOKEN_SHAPES = [
  /\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{4,}/g,
  /(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})/g,
  // `x-access-token:<token>` in base64, as Git sends it and a Git trace shows it.
  /eC1hY2Nlc3MtdG9rZW46[A-Za-z0-9+/]*={0,2}/g,
];

/**
 * Generic secret shapes — a separate list so GitHub shapes stay intact.
 *
 * Supported patterns (documented, not exhaustive):
 *  • Authorization/Bearer header values:
 *      Authorization: Bearer <value>  |  Authorization: Token <value>
 *  • Common API key vendor prefixes (at a word boundary):
 *      sk-…  (OpenAI and compatible)
 *      AKIA… (AWS access key id)
 *      xoxa-/xoxb-/xoxp-/xoxr-/xoxs- (Slack)
 *      AIza… (Google API key)
 *  • JSON Web Tokens: three base64url segments separated by dots
 *  • PEM private-key blocks:
 *      -----BEGIN … PRIVATE KEY----- … -----END … PRIVATE KEY-----
 *      or through the end of the text when the END line was cut off
 *  • URL credentials: scheme://user:password@host — password masked, user kept
 *  • Key=value secret assignments (JSON, env-var, CLI flag forms):
 *      password=, passwd=, secret=, token=, api_key=, api-key=, also inside a
 *      longer name (DB_PASSWORD=, client_secret=, AWS_SECRET_ACCESS_KEY=),
 *      followed by a non-whitespace value. A keyword followed by a letter
 *      (max_tokens=, tokenizer=) is not a secret name; a few harmless names
 *      such as token_count= are masked anyway.
 *
 * Split-across-chunks safety: these patterns are applied to completed text.
 * Tool detail is only published after an item completes, so a secret split
 * across stream chunks is always reassembled before redactGenericShapes runs.
 * The existing unfinished() / cutTail() pair handles exact-value splits in
 * live streaming; generic shapes do not need the same mechanism here.
 */
/**
 * Patterns where the ENTIRE match is the secret and should be replaced whole.
 * Prefix shapes (sk-, AKIA, etc.) and JWT / PEM blocks land here.
 */
const FULL_MATCH_SHAPES: readonly RegExp[] = [
  // Common vendor API key prefixes (at a word boundary)
  /\bsk-[A-Za-z0-9_-]{16,}/g,
  /\bAKIA[A-Z0-9]{12,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{8,}/g,
  /\bAIza[A-Za-z0-9_-]{30,}/g,

  // JSON Web Tokens: header.payload.signature (base64url, each segment >= 4 chars)
  /\beyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_.-]{8,}/g,

  // PEM private-key block (single- or multi-line; lazy inner match), through
  // the end of the text when the END line was cut off
  /-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----[\s\S]*?(?:-----END(?: [A-Z]+)* PRIVATE KEY-----|$)/g,
];

/**
 * A secret's name, at the start of a word: one of the keywords, inside a
 * longer name or not, but not followed by a letter, so `max_tokens` and
 * `tokenizer` are not one. Nothing word-like before it, so a long run of word
 * characters is tried from its start only, and a bounded name around the
 * keyword, so that one try is not a scan of the whole run per keyword in it.
 */
const SECRET_NAME =
  '(?<![\\w-])[\\w-]{0,64}?(?:password|passwd|secret|token|api[_-]?key)(?![A-Za-z])[\\w-]{0,64}';

/**
 * Patterns that keep what names the secret and mask only the secret: each is
 * a regex and its replacement, which puts back the kept capture group(s).
 */
const PREFIX_SECRET_SHAPES: readonly [RegExp, string][] = [
  // Authorization header: keep "Authorization: Bearer " prefix, mask value.
  [
    /(\b[Aa]uthorization\s*[:=]\s*(?:Bearer|Token|Basic|Digest)\s+)[A-Za-z0-9+/_.~=%-]{8,}/g,
    '$1[REDACTED]',
  ],

  // Bare Bearer keyword in a log line: keep "Bearer ", mask value.
  [/(\bBearer\s+)[A-Za-z0-9+/_.~=%-]{8,}/g, '$1[REDACTED]'],

  // URL credentials: keep scheme://user, mask password, keep @. The scheme and
  // password are bounded so a long run is not rescanned from every position.
  [/(\b[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/[^/:@\s]+):[^@\s]{3,256}@/g, '$1:[REDACTED]@'],

  // Key=value JSON string form: "password":"value"  — keep the key+delimiter, mask value.
  [new RegExp(`(${SECRET_NAME}\\s*["']?\\s*:\\s*["'])[^"',;\\s]{4,}`, 'gi'), '$1[REDACTED]'],

  // Key=value env-var / CLI flag form: password=value  --token=value  DB_PASSWORD=value
  [new RegExp(`(${SECRET_NAME}\\s*=\\s*)[^\\s,;&|'"]{4,}`, 'gi'), '$1[REDACTED]'],
];

/** Redact all generic secret shapes from `text`: whole matches, then the secret part of prefixed ones. */
function redactGenericShapes(text: string): string {
  const masked = FULL_MATCH_SHAPES.reduce(
    (output, shape) => output.replace(shape, '[REDACTED]'),
    text
  );
  return PREFIX_SECRET_SHAPES.reduce(
    (output, [shape, replacement]) => output.replace(shape, replacement),
    masked
  );
}

const CUT_TAIL_MIN = 8;

function redactShapes(text: string): string {
  return TOKEN_SHAPES.reduce((output, shape) => output.replace(shape, '[REDACTED]'), text);
}

/**
 * The service tokens a process has handed out, in every form, to scrub wherever
 * it writes, and anything shaped like a GitHub token besides.
 */
export class Redactions {
  private readonly values = new Set<string>();

  add(token: string): void {
    for (const form of tokenForms(token)) this.values.add(form);
  }

  /** Values another holder listed, already in every form: a session takes its host's. */
  addListed(values: readonly string[]): void {
    for (const value of values) if (value) this.values.add(value);
  }

  list(): string[] {
    return [...this.values];
  }

  text(input: string): string {
    if (!this.values.size) return redactGenericShapes(redactShapes(input));
    return redactGenericShapes(redactShapes(this.cutTail(redactText(input, this.list()))));
  }

  /**
   * `input` with its end redacted when that end is the start of a value held
   * here, before a closing ellipsis or not: what a title cut short through a
   * token leaves, which no exact match finds. Eight characters or more, so
   * ordinary text that happens to end the way a token begins is left alone.
   */
  private cutTail(input: string): string {
    const ellipsis = input.endsWith('…') ? '…' : '';
    const body = ellipsis ? input.slice(0, -1) : input;
    const held = this.unfinished(body);
    return held >= CUT_TAIL_MIN
      ? `${body.slice(0, body.length - held)}[REDACTED]${ellipsis}`
      : input;
  }

  /**
   * How many characters at the end of `text` could be the start of a value
   * held here: text still streaming in holds them back, so a token arriving
   * over several chunks is never shown in part.
   */
  unfinished(text: string): number {
    let longest = 0;
    for (const value of this.values)
      for (let length = Math.min(value.length - 1, text.length); length > longest; length--)
        if (text.endsWith(value.slice(0, length))) {
          longest = length;
          break;
        }
    return longest;
  }

  /** `input` with every string in it redacted: for JSON values, such as a tool call's arguments. */
  value<T>(input: T): T {
    const walk = (value: unknown): unknown => {
      if (typeof value === 'string') return this.text(value);
      if (Array.isArray(value)) return value.map(walk);
      if (value !== null && typeof value === 'object')
        return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, walk(item)]));
      return value;
    };
    return walk(input) as T;
  }
}

/**
 * Streaming exact-value redaction. It retains at most one byte less than the
 * longest secret, which is enough to decide whether a secret continues in the
 * next chunk. `secrets` is read on every chunk, so a value added later is
 * scrubbed from everything written after it was added.
 */
export class LogRedactor {
  private pending = Buffer.alloc(0);
  private seen: readonly string[] = [];
  private secrets: Buffer[] = [];

  constructor(private readonly source: () => readonly string[]) {}

  private current(): Buffer[] {
    const values = this.source();
    if (values.length !== this.seen.length) {
      this.seen = values;
      this.secrets = secretBuffers(values);
    }
    return this.secrets;
  }

  push(chunk: Buffer): Buffer {
    const secrets = this.current();
    const combined = Buffer.concat([this.pending, chunk]);
    const retained = Math.max(0, ...secrets.map((secret) => secret.length - 1));
    const scanLimit = Math.max(0, combined.length - retained);
    const { output, consumed } = redactPrefix(combined, scanLimit, secrets);
    this.pending = Buffer.from(combined.subarray(consumed));
    return output;
  }

  finish(): Buffer {
    const output = redactPrefix(this.pending, this.pending.length, this.current()).output;
    this.pending = Buffer.alloc(0);
    return output;
  }
}

/** How much of a line without its end is held for shape redaction before it is written anyway. */
const SHAPE_LINE_LIMIT = 64 * 1024;

/**
 * Streaming redaction of GitHub's token shapes, a line at a time: a token
 * issued before this host started, which no exact value names, split over
 * chunks is still whole within its line. Bytes are read as latin1, one
 * character each, so a line held past `SHAPE_LINE_LIMIT` is never cut inside
 * a UTF-8 character's bytes when it is put back.
 */
export class ShapeLineRedactor {
  private pending = Buffer.alloc(0);

  push(chunk: Buffer): Buffer {
    const combined = Buffer.concat([this.pending, chunk]);
    const end = combined.lastIndexOf(0x0a) + 1;
    const cut = end > 0 ? end : combined.length > SHAPE_LINE_LIMIT ? longLineCut(combined) : 0;
    this.pending = Buffer.from(combined.subarray(cut));
    return redactShapeBytes(combined.subarray(0, cut));
  }

  finish(): Buffer {
    const output = redactShapeBytes(this.pending);
    this.pending = Buffer.alloc(0);
    return output;
  }
}

/** Longer than any token's form a shape matches, base64 of a fine-grained one included. */
const SHAPE_TAIL = 256;

/**
 * Where to cut a line written before its end: short of its last
 * `SHAPE_TAIL` bytes, and short of any token-shaped text reaching into them,
 * which may go on in the next chunk and is held back whole.
 */
function longLineCut(line: Buffer): number {
  const text = line.toString('latin1');
  let cut = text.length - SHAPE_TAIL;
  // A run longer than any token is not one, and is not held back.
  for (const shape of TOKEN_SHAPES)
    for (const match of text.matchAll(shape))
      if (match.index + match[0].length > cut && cut - match.index <= SHAPE_TAIL)
        cut = Math.min(cut, match.index);
  return Math.max(cut, 0);
}

function redactShapeBytes(input: Buffer): Buffer {
  return input.length ? Buffer.from(redactShapes(input.toString('latin1')), 'latin1') : input;
}

async function consume(
  stream: Readable,
  file: FileHandle,
  secrets: () => readonly string[]
): Promise<void> {
  const redactor = new LogRedactor(secrets);
  const shapes = new ShapeLineRedactor();
  for await (const chunk of stream) {
    const output = shapes.push(redactor.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    if (output.length) await file.write(output);
  }
  const output = Buffer.concat([shapes.push(redactor.finish()), shapes.finish()]);
  if (output.length) await file.write(output);
}

/** Copy each stream into `file`, scrubbing the values `secrets` holds as each chunk is written. */
export async function pipeRedactedLogs(
  streams: Readable[],
  file: FileHandle,
  secrets: () => readonly string[]
): Promise<void> {
  await Promise.all(streams.map((stream) => consume(stream, file, secrets)));
}
