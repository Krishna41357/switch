import type { HostBody, Item, Origin, Session } from '@switch-console/shared/session-v1';
import type { ProviderRuntimeEvent } from '../events';
import type { Redactions } from '../host/redaction';
import type { ToolDetailBuffer } from '../host/tool-detail-buffer';

type TurnContext = { commandId: string | null; origin: Origin | null };
type BufferedItem = {
  item: Item;
  emittedAt: number;
  dirty: boolean;
  parts: number;
  nativeId: string;
};

/** A tool item's published detail, in characters: inside one 4096-character part, note included. */
export const TOOL_DETAIL_LIMIT = 4000;
/** Room kept for the truncation note, which is under 40 characters. */
const TOOL_DETAIL_NOTE = 48;
export const TOOL_DETAIL_WITHHELD = '[tool detail withheld: it could not be redacted]';

/** Projects chat and tool summaries only. The host owns sequencing and durable publication. */
export class ChatProjector {
  private readonly turns = new Map<string, TurnContext>();
  private readonly items = new Map<string, BufferedItem>();
  private readonly hidden = new Set<string>();

  /**
   * `redactions`, the service tokens the session was handed, are scrubbed
   * from an assistant message's whole text before it is split into parts,
   * and text still streaming in holds back what could be the start of one,
   * so no published revision or part carries a token in pieces.
   *
   * `toolDetails`, when given, is where a tool item's text comes from: what
   * the call was given and gave back, redacted and capped. When null a tool
   * item carries its title only.
   */
  constructor(
    private readonly session: Session,
    private readonly redactions: Redactions | null,
    private readonly toolDetails: ToolDetailBuffer | null = null
  ) {}

  bindTurn(turnId: string, context: TurnContext): void {
    if (this.turns.has(turnId)) throw new Error('Turn is already bound.');
    this.turns.set(turnId, structuredClone(context));
  }

  ingest(event: ProviderRuntimeEvent, now: number): HostBody[] {
    if (event.sessionId !== this.session.sessionId || event.provider !== this.session.provider)
      throw new Error('Provider event identity mismatch.');
    switch (event.type) {
      case 'session.state.changed':
        this.session.status = event.status;
        return [{ type: 'session.upsert', session: structuredClone(this.session) }];
      case 'session.exited':
        if (this.session.status !== 'error') this.session.status = 'stopped';
        return [
          ...this.flush(now, true),
          { type: 'session.upsert', session: structuredClone(this.session) },
        ];
      case 'turn.started':
        return [
          {
            type: 'turn.upsert',
            turnId: event.turnId,
            status: 'running',
            commandId: this.context(event.turnId).commandId,
          },
        ];
      case 'turn.completed':
        return [
          ...this.flush(now, true),
          {
            type: 'turn.upsert',
            turnId: event.turnId,
            status: event.outcome,
            commandId: this.context(event.turnId).commandId,
          },
        ];
      case 'item.started':
      case 'item.updated':
      case 'item.completed': {
        const key = JSON.stringify([event.turnId, event.item.id]);
        if (event.item.type === 'reasoning') {
          this.hidden.add(key);
          return [];
        }
        const context = this.context(event.turnId);
        const previous = this.items.get(key);
        const kind =
          event.item.type === 'assistant_message'
            ? 'assistant-message'
            : event.item.type === 'user_message'
              ? 'user-message'
              : 'tool-activity';
        // Raw tool output and vendor payloads are not a shared tool summary.
        const title = event.item.title.slice(0, 4096);
        const item: Item = {
          itemId: key,
          turnId: event.turnId,
          revision: previous?.item.revision ?? 0,
          kind,
          status: event.item.status === 'in_progress' ? 'in-progress' : event.item.status,
          // With tool detail on, the command in a title is masked as its detail is.
          title:
            kind === 'tool-activity' && this.toolDetails && this.redactions
              ? this.redactions.secrets(title)
              : title,
          text: kind === 'tool-activity' ? '' : (event.item.text ?? previous?.item.text ?? ''),
          attachments: [],
          origin: kind === 'user-message' ? context.origin : null,
        };
        const buffered = {
          item,
          emittedAt: previous?.emittedAt ?? -Infinity,
          dirty: true,
          parts: previous?.parts ?? 1,
          nativeId: event.item.id,
        };
        this.items.set(key, buffered);
        return this.emitItem(buffered, now, event.type === 'item.completed');
      }
      case 'content.delta': {
        const key = JSON.stringify([event.turnId, event.itemId]);
        if (this.hidden.has(key)) return [];
        const buffered = this.items.get(key);
        if (!buffered || buffered.item.kind !== 'assistant-message')
          throw new Error('Text delta has no assistant item.');
        buffered.item.text += event.delta;
        buffered.dirty = true;
        return this.emitItem(buffered, now, false);
      }
      case 'item.delta': {
        // Tool output and reasoning stay on the execution host, unless tool detail is on.
        if (!this.toolDetails) return [];
        const buffered = this.items.get(JSON.stringify([event.turnId, event.itemId]));
        if (!buffered || buffered.item.kind !== 'tool-activity') return [];
        buffered.dirty = true;
        return this.emitItem(buffered, now, false);
      }
      default:
        return [];
    }
  }

  /** Call on a 250ms host tick, and before publishing terminal state. */
  flush(now: number, final: boolean): HostBody[] {
    return [...this.items.values()].flatMap((item) => this.emitItem(item, now, final));
  }

  private emitItem(buffer: BufferedItem, now: number, final: boolean): HostBody[] {
    if (!buffer.dirty || (!final && now - buffer.emittedAt < 250)) return [];
    buffer.item.revision += 1;
    buffer.emittedAt = now;
    buffer.dirty = false;
    if (this.toolDetails && buffer.item.kind === 'tool-activity')
      buffer.item.text = this.toolText(this.toolDetails, buffer, final);
    const characters = Array.from(this.visible(buffer.item.text, final));
    const count = Math.max(1, Math.ceil(characters.length / 4096), buffer.parts);
    buffer.parts = count;
    return Array.from({ length: count }, (_, index) => ({
      type: 'item.upsert' as const,
      item: {
        ...structuredClone(buffer.item),
        itemId: index === 0 ? buffer.item.itemId : `${buffer.item.itemId}:part:${index}`,
        text: characters.slice(index * 4096, (index + 1) * 4096).join(''),
      },
    }));
  }

  /**
   * What a tool call was given and gave back, as the host's buffer holds it.
   * Redacted whole before it is cut, so a secret the cut goes through is
   * already masked: each input string first, so one clipped short is caught
   * by its cut tail, then the input's JSON, so a value is caught by its key.
   * Until `final`, output only up to its last line break: a secret the shapes
   * would match whole is not shown in part while its line is still arriving.
   * Nothing without redactions, and a notice in place of the detail when
   * redaction fails.
   */
  private toolText(toolDetails: ToolDetailBuffer, buffer: BufferedItem, final: boolean): string {
    const detail = toolDetails.detail(this.session.epoch, buffer.item.turnId, buffer.nativeId);
    if (!detail || !this.redactions) return '';
    let text: string;
    try {
      const sections: string[] = [];
      const redactions = this.redactions;
      if (detail.input !== null)
        sections.push(
          `Input: ${redactions.secrets(redactions.text(JSON.stringify(redactions.value(detail.input))))}`
        );
      const output =
        detail.output !== null && !final
          ? detail.output.slice(0, detail.output.lastIndexOf('\n') + 1)
          : detail.output;
      if (output) sections.push(`Output:\n${redactions.secrets(redactions.text(output))}`);
      text = sections.join('\n\n');
    } catch {
      return TOOL_DETAIL_WITHHELD;
    }
    const characters = Array.from(text);
    if (characters.length <= TOOL_DETAIL_LIMIT) return text;
    const kept = TOOL_DETAIL_LIMIT - TOOL_DETAIL_NOTE;
    return `${characters.slice(0, kept).join('')}\n[truncated, ${characters.length - kept} more characters]`;
  }

  private visible(text: string, final: boolean): string {
    if (!this.redactions) return text;
    const held = final ? 0 : this.redactions.unfinished(text);
    return this.redactions.text(text.slice(0, text.length - held));
  }

  private context(turnId: string): TurnContext {
    const context = this.turns.get(turnId);
    if (!context) throw new Error('Bind verified command origin before processing the turn.');
    return context;
  }
}
