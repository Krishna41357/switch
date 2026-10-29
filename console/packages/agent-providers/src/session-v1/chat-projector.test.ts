import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Session } from '@switch-console/shared/session-v1';
import { describe, expect, it } from 'vitest';
import type { ProviderRuntimeEvent } from '../events';
import { Redactions } from '../host/redaction';
import { ToolDetailBuffer } from '../host/tool-detail-buffer';
import { ChatProjector } from './chat-projector';
import { TOOL_DETAIL_LIMIT, TOOL_DETAIL_WITHHELD } from './chat-projector';
import { EventOutbox } from './event-outbox';

const session = (provider: Session['provider']): Session => ({
  sessionId: 'session',
  epoch: 'epoch',
  agentId: 'agent',
  hostId: 'host',
  provider,
  status: 'ready',
  connectivity: 'online',
  capabilities: {
    input: 'queue',
    approvals: false,
    questions: false,
    interrupt: true,
    reset: false,
    compact: false,
    modelChange: false,
    attachmentMimeTypes: [],
  },
  pendingRequestIds: [],
});
const context = {
  commandId: 'command',
  origin: {
    surface: 'mattermost' as const,
    actorId: 'actor',
    roomId: 'room',
    threadId: 'thread',
    messageId: 'message',
  },
};

describe('chat projection', () => {
  it.each(['claude', 'codex', 'opencode', 'antigravity', 'cursor'] as const)(
    'projects %s text with bounded full replacements and immediate final state',
    (provider) => {
      const projector = new ChatProjector(session(provider), null);
      projector.bindTurn('turn', context);
      const base = {
        provider,
        sessionId: 'session',
        eventId: 'native-event',
        createdAt: '2026-09-07T12:00:00Z',
        turnId: 'turn',
      };
      const first = projector.ingest(
        {
          ...base,
          type: 'item.started',
          item: {
            id: 'answer',
            type: 'assistant_message',
            status: 'in_progress',
            title: '',
            text: '',
          },
        },
        0
      );
      expect(first).toHaveLength(1);
      expect(
        projector.ingest({ ...base, type: 'content.delta', itemId: 'answer', delta: 'Hello' }, 10)
      ).toEqual([]);
      const update = projector.ingest(
        { ...base, type: 'content.delta', itemId: 'answer', delta: ' world' },
        250
      )[0];
      expect(update).toMatchObject({
        type: 'item.upsert',
        item: {
          text: 'Hello world',
          revision: 2,
          origin: null,
        },
      });
      expect(
        projector.ingest(
          {
            ...base,
            type: 'item.completed',
            item: {
              id: 'answer',
              type: 'assistant_message',
              status: 'completed',
              title: '',
              text: 'Hello world!',
            },
          },
          260
        )[0]
      ).toMatchObject({ item: { revision: 3, status: 'completed', text: 'Hello world!' } });
    }
  );
  it('excludes reasoning and tool payload/output while preserving verified user origin', () => {
    const projector = new ChatProjector(session('claude'), null);
    projector.bindTurn('turn', context);
    const base = {
      provider: 'claude',
      sessionId: 'session',
      eventId: 'native-event',
      createdAt: '2026-09-07T12:00:00Z',
      turnId: 'turn',
    };
    expect(
      projector.ingest(
        {
          ...base,
          type: 'item.started',
          item: {
            id: 'thought',
            type: 'reasoning',
            status: 'in_progress',
            title: 'Private',
            text: 'Private',
          },
        },
        0
      )
    ).toEqual([]);
    const output = projector.ingest(
      {
        ...base,
        type: 'item.completed',
        raw: { source: 'sdk', payload: { secret: 'private' } },
        item: {
          id: 'tool',
          type: 'command_execution',
          status: 'completed',
          title: 'Run tests',
          text: 'raw output',
          payload: { secret: 'private' },
        },
      },
      0
    );
    expect(JSON.stringify(output)).not.toMatch(/raw output|private|payload/);
    expect(
      projector.ingest(
        {
          ...base,
          type: 'item.completed',
          item: { id: 'user', type: 'user_message', status: 'completed', title: '', text: 'Hello' },
        },
        0
      )[0]
    ).toMatchObject({ item: { origin: context.origin } });
    expect(() =>
      projector.ingest(
        { ...base, sessionId: 'wrong', type: 'turn.started' } as ProviderRuntimeEvent,
        0
      )
    ).toThrow('identity');
  });
});

it('persists host sequences and acknowledgements across reloads', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'session-outbox-'));
  try {
    const path = join(dir, 'events.jsonl');
    const outbox = await EventOutbox.load(path, 'session', 'epoch');
    const body = { type: 'session.upsert' as const, session: session('claude') };
    await Promise.all([
      outbox.append(body, '2026-09-07T12:00:00Z'),
      outbox.append(body, '2026-09-07T12:00:01Z'),
    ]);
    await expect(outbox.acknowledge(3)).rejects.toThrow('Invalid');
    await outbox.acknowledge(1);
    const recovered = await EventOutbox.load(path, 'session', 'epoch');
    expect(recovered.pending().map((x) => x.hostSequence)).toEqual([2]);
    expect((await recovered.append(body, '2026-09-07T12:00:02Z')).hostSequence).toBe(3);
    expect((await readFile(path, 'utf8')).split('\n').filter(Boolean)).toHaveLength(4);
    await expect(EventOutbox.load(path, 'other', 'epoch')).rejects.toThrow('identity');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

it('preserves a long Unicode response in bounded wire items', () => {
  const projector = new ChatProjector(session('claude'), null);
  projector.bindTurn('turn', context);
  const text = '😀\n"'.repeat(20000);
  const events = projector.ingest(
    {
      provider: 'claude',
      sessionId: 'session',
      eventId: 'large',
      createdAt: '2026-09-07T12:00:00Z',
      turnId: 'turn',
      type: 'item.completed',
      item: { id: 'answer', type: 'assistant_message', status: 'completed', title: '', text },
    },
    0
  );
  expect(
    events.map((event) => (event.type === 'item.upsert' ? event.item.text : '')).join('')
  ).toBe(text);
  for (const event of events)
    expect(Buffer.byteLength(JSON.stringify(event))).toBeLessThan(60 * 1024);
});

describe('service tokens in streamed text', () => {
  const TOKEN = 'synthetic-installation-token-0123456789';
  const base = {
    provider: 'claude' as const,
    sessionId: 'session',
    eventId: 'native-event',
    createdAt: '2026-09-07T12:00:00Z',
    turnId: 'turn',
  };
  const texts = (bodies: ReturnType<ChatProjector['ingest']>) =>
    bodies.flatMap((body) => (body.type === 'item.upsert' ? [body.item.text] : []));

  function projector() {
    const redactions = new Redactions();
    redactions.add(TOKEN);
    const projected = new ChatProjector(session('claude'), redactions);
    projected.bindTurn('turn', context);
    return projected;
  }

  it('never publishes part of a token that arrives over several chunks', () => {
    const p = projector();
    const published = texts(
      p.ingest(
        {
          ...base,
          type: 'item.started',
          item: {
            id: 'answer',
            type: 'assistant_message',
            status: 'in_progress',
            title: '',
            text: '',
          },
        },
        0
      )
    );
    const chunks = [
      'The token is ',
      TOKEN.slice(0, 12),
      TOKEN.slice(12, 25),
      TOKEN.slice(25),
      ' ok',
    ];
    chunks.forEach((delta, index) =>
      published.push(
        ...texts(
          p.ingest({ ...base, type: 'content.delta', itemId: 'answer', delta }, (index + 1) * 300)
        )
      )
    );
    published.push(...texts(p.flush(10_000, true)));
    expect(published.at(-1)).toBe('The token is [REDACTED] ok');
    for (const text of published) expect(text).not.toContain(TOKEN.slice(0, 8));
  });

  it('scrubs a token before a long message is split into parts', () => {
    const p = projector();
    const text = `${'a'.repeat(4096 - 10)}${TOKEN} done`;
    const parts = texts(
      p.ingest(
        {
          ...base,
          type: 'item.completed',
          item: { id: 'answer', type: 'assistant_message', status: 'completed', title: '', text },
        },
        0
      )
    );
    expect(parts.join('')).toBe(`${'a'.repeat(4096 - 10)}[REDACTED] done`);
    for (const part of parts) expect(part).not.toContain(TOKEN.slice(-8));
  });
});

describe('tool detail', () => {
  // Built at runtime so no key-shaped literal appears in source.
  const TOKEN = 'synthetic-installation-token-0123456789';
  const PASSWORD = 'hunter2' + 'secret';
  const base = {
    provider: 'codex' as const,
    sessionId: 'session',
    eventId: 'native-event',
    createdAt: '2026-09-07T12:00:00Z',
    turnId: 'turn',
  };
  const texts = (bodies: ReturnType<ChatProjector['ingest']>) =>
    bodies.flatMap((body) => (body.type === 'item.upsert' ? [body.item.text] : []));
  const tool = (
    status: 'in_progress' | 'completed',
    text: string,
    payload: Record<string, unknown> = { command: 'ls' }
  ) => ({
    ...base,
    type: status === 'completed' ? ('item.completed' as const) : ('item.started' as const),
    item: { id: 'tool', type: 'command_execution' as const, status, title: 'ls', text, payload },
  });

  /** Feeds the buffer before the projector, as the session host does. */
  function setup(redactions: Redactions | null = new Redactions()) {
    redactions?.add(TOKEN);
    const buffer = new ToolDetailBuffer();
    const projector = new ChatProjector(session('codex'), redactions, buffer);
    projector.bindTurn('turn', context);
    return (event: ProviderRuntimeEvent, now: number) => {
      buffer.ingest(event, 'epoch');
      return projector.ingest(event, now);
    };
  }

  it('is not published when off, whatever the call output', () => {
    const projector = new ChatProjector(session('codex'), new Redactions(), null);
    projector.bindTurn('turn', context);
    expect(texts(projector.ingest(tool('in_progress', 'out'), 0))).toEqual(['']);
    expect(
      projector.ingest({ ...base, type: 'item.delta', itemId: 'tool', delta: 'more' }, 1000)
    ).toEqual([]);
    expect(texts(projector.ingest(tool('completed', 'raw output'), 2000))).toEqual(['']);
  });

  it('publishes the input and output of a call when on', () => {
    const feed = setup();
    expect(texts(feed(tool('completed', 'file1\nfile2'), 0))).toEqual([
      'Input: {"command":"ls"}\n\nOutput:\nfile1\nfile2',
    ]);
  });

  it('masks secrets in the input and output, by value and by shape', () => {
    const feed = setup();
    const [text] = texts(
      feed(
        tool('completed', `connecting to postgres://app:${PASSWORD}@db/main as ${TOKEN}`, {
          command: 'psql',
          env: { db_password: PASSWORD },
        }),
        0
      )
    );
    expect(text).toBe(
      'Input: {"command":"psql","env":{"db_password":"[REDACTED]"}}\n\n' +
        'Output:\nconnecting to postgres://app:[REDACTED]@db/main as [REDACTED]'
    );
  });

  it('cuts a large output to one part, with a note of what was left out', () => {
    const feed = setup();
    const bodies = feed(tool('completed', 'x'.repeat(10_000)), 0);
    expect(bodies).toHaveLength(1);
    const [text] = texts(bodies);
    expect(Array.from(text).length).toBeLessThanOrEqual(TOOL_DETAIL_LIMIT);
    const full = `Input: {"command":"ls"}\n\nOutput:\n${'x'.repeat(6 * 1024)}\n…\n${'x'.repeat(2 * 1024)}`;
    const shown = text.slice(0, text.lastIndexOf('\n[truncated'));
    expect(full.startsWith(shown)).toBe(true);
    expect(text.endsWith(`\n[truncated, ${full.length - shown.length} more characters]`)).toBe(
      true
    );
  });

  it('masks a secret the cut goes through before cutting', () => {
    const feed = setup();
    const prefix = 'Input: {"command":"ls"}\n\nOutput:\n';
    const key = 'sk-' + 'Abcdefghijk' + 'lmnopqrstuvwxyz01234';
    const lead = 'a'.repeat(TOOL_DETAIL_LIMIT - 48 - prefix.length - 6);
    const [text] = texts(feed(tool('completed', `${lead}${key} ${TOKEN} ${'b'.repeat(500)}`), 0));
    expect(text).toContain('[truncated,');
    expect(text).not.toContain(key.slice(0, 8));
    expect(text).not.toContain(TOKEN.slice(0, 8));
  });

  it('streams output deltas, throttled, without showing part of a token', () => {
    const feed = setup();
    const published = texts(feed(tool('in_progress', ''), 0));
    const chunks = ['token ', TOKEN.slice(0, 12), TOKEN.slice(12, 25), TOKEN.slice(25), ' ok'];
    chunks.forEach((delta, index) =>
      published.push(
        ...texts(feed({ ...base, type: 'item.delta', itemId: 'tool', delta }, (index + 1) * 300))
      )
    );
    expect(texts(feed({ ...base, type: 'item.delta', itemId: 'tool', delta: '!' }, 1510))).toEqual(
      []
    );
    published.push(...texts(feed(tool('completed', ''), 2000)));
    expect(published.at(-1)).toBe('Input: {"command":"ls"}\n\nOutput:\ntoken [REDACTED] ok!');
    for (const text of published) expect(text).not.toContain(TOKEN.slice(0, 8));
  });

  it('masks a secret in the title of a tool call only when on', () => {
    const value = 'abcdef' + 'ghijklmn';
    const title = `curl -H "Authorization: Bearer ${value}" https://api.example.com`;
    const event = {
      ...base,
      type: 'item.completed' as const,
      item: { id: 'tool', type: 'command_execution' as const, status: 'completed' as const, title },
    };
    const titles = (bodies: ReturnType<ChatProjector['ingest']>) =>
      bodies.flatMap((body) => (body.type === 'item.upsert' ? [body.item.title] : []));
    const off = new ChatProjector(session('codex'), new Redactions(), null);
    off.bindTurn('turn', context);
    expect(titles(off.ingest(event, 0))).toEqual([title]);
    expect(titles(setup()(event, 0))).toEqual([
      'curl -H "Authorization: Bearer [REDACTED]" https://api.example.com',
    ]);
  });

  it('publishes nothing without redactions to apply', () => {
    const feed = setup(null);
    expect(texts(feed(tool('completed', 'out'), 0))).toEqual(['']);
  });

  it('withholds the detail when redaction fails', () => {
    class Failing extends Redactions {
      override value<T>(_input: T): T {
        throw new Error('simulated redaction failure');
      }
    }
    const feed = setup(new Failing());
    expect(texts(feed(tool('completed', 'out'), 0))).toEqual([TOOL_DETAIL_WITHHELD]);
  });

  /** Every text published while `deltas` stream in 300 ms apart, then on completion. */
  function stream(deltas: string[]): string[] {
    const feed = setup();
    const published = texts(feed(tool('in_progress', ''), 0));
    deltas.forEach((delta, index) =>
      published.push(
        ...texts(feed({ ...base, type: 'item.delta', itemId: 'tool', delta }, (index + 1) * 300))
      )
    );
    published.push(...texts(feed(tool('completed', ''), 10_000)));
    return published;
  }

  it('publishes streamed output by whole lines, so no secret shows in part', () => {
    const url = 'postgres://app:' + PASSWORD + '@db/main';
    const assignment = 'DB_PASSWORD=' + PASSWORD;
    const published = stream([
      'url: ' + url.slice(0, url.indexOf(':', 12) + 6),
      url.slice(url.indexOf(':', 12) + 6) + '\n',
      assignment.slice(0, 'DB_PASSWORD='.length + 4),
      assignment.slice('DB_PASSWORD='.length + 4) + '\n',
    ]);
    expect(published.length).toBeGreaterThan(2);
    for (const text of published) expect(text).not.toContain(PASSWORD.slice(0, 3));
    expect(published.at(-1)).toBe(
      'Input: {"command":"ls"}\n\nOutput:\n' +
        'url: postgres://app:[REDACTED]@db/main\nDB_PASSWORD=[REDACTED]\n'
    );
  });

  it('never shows the body of a private key streamed in pieces', () => {
    const body = 'MIIEow' + 'IBAAKCAQEA0Z3VS5JJ';
    const published = stream([
      '-----BEGIN RSA ',
      'PRIVATE KEY-----\n' + body.slice(0, 8),
      body.slice(8) + '\n',
      '-----END RSA ' + 'PRIVATE KEY-----\ndone\n',
    ]);
    expect(published.length).toBeGreaterThan(2);
    for (const text of published) expect(text).not.toContain(body.slice(0, 4));
    expect(published.at(-1)).toBe('Input: {"command":"ls"}\n\nOutput:\n[REDACTED]\ndone\n');
  });
});
