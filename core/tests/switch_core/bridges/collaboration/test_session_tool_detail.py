"""A tool call's detail, where a session publishes its input and output.

The host sends it already redacted and already cut to 4,000 characters with a
note saying how much it left out. What is left to the renderers is to show it
as it is: on Slack in the card a reader expands, all of it, as literal text;
on a platform whose log is body text as a preview folded onto the call's one
line. The status line beside a running turn shows titles only, as before.
"""

from __future__ import annotations

import json
from typing import Any

from switch_core.bridges.collaboration.session.renderers import MARKDOWN
from switch_core.bridges.collaboration.session.renderers.neutral import (
    activity_log,
    turn_status,
)
from switch_core.bridges.collaboration.session.renderers.slack import (
    _MAX_POST_BYTES,
    _MAX_SECTION_ITEMS,
    _MAX_STREAM_BYTES,
    StreamedActivity,
    render_activity_plan,
    render_activity_stream,
)
from switch_core.sessions.contract import Item

from .session_fixtures import _item, _turn

# Built at runtime so no key-shaped literal appears in source.
PASSWORD = "hunter2" + "secret"


def _call(text: str, *, title: str = "Ran a command", item_id: str = "call") -> Item:
    return _item(itemId=item_id, kind="tool-activity", title=title, text=text)


def _card(item: Item) -> dict[str, Any]:
    """The one card a turn of `item` draws, after the session card."""
    tasks = render_activity_plan([item], _turn("completed")).blocks[0]["tasks"]
    assert tasks[0]["task_id"] == "switch-session"
    card = tasks[1]
    assert isinstance(card, dict)
    return card


def _detail(card: dict[str, Any]) -> str:
    text = card["details"]["elements"][0]["elements"][0]["text"]
    assert isinstance(text, str)
    return text


def _identity(text: str) -> str:
    return text


def _log(items: list[Item]) -> list[str]:
    return activity_log(
        items,
        _turn("completed"),
        escape=_identity,
        limit=10_000,
        markup=MARKDOWN,
        elapsed_seconds=None,
        heading=False,
    ).splitlines()


# ── Slack: the card holds the detail as it was published ──────────────────────


async def test_a_card_shows_a_command_exactly_as_it_ran() -> None:
    """Markdown-looking characters in output are the output, not emphasis.

    A card's detail renders no markup, so stripping it would only change what
    the reader is told ran: `s/_old_/_new_/` read back as `s/old/new/`.
    """
    for text in (
        'cat file | sed "s/_old_/_new_/"',
        "echo $((a * b * c))",
        "grep -n `whoami` src",
        "Output:\n    indented line\n        more indented",
    ):
        assert _detail(_card(_call(text))) == text


async def test_a_card_leaves_redactions_markup_and_json_alone() -> None:
    text = (
        'Input: {"command":"psql","env":{"PGPASSWORD":"[REDACTED]"}}\n\n'
        "Output:\nconnecting to postgres://app:[REDACTED]@db/main\n"
        "<ok> && done"
    )
    assert _detail(_card(_call(text))) == text


async def test_a_mention_in_output_stays_literal_text() -> None:
    """The detail is a rich-text text element, which Slack does not parse."""
    card = _card(_call("Output:\n<!here> deploy finished"))
    element = card["details"]["elements"][0]["elements"][0]
    assert element == {"type": "text", "text": "Output:\n<!here> deploy finished"}


async def test_the_detail_is_trimmed_at_its_ends_only() -> None:
    assert (
        _detail(_card(_call("  \n  line one\n  line two  \n")))
        == "line one\n  line two"
    )


async def test_a_title_is_still_stripped_of_markup() -> None:
    """Only the detail changed: a title is still drawn as plain words."""
    assert _card(_call("out", title="Ran `npm test` for **all**"))["title"] == (
        "Ran npm test for all"
    )


async def test_a_published_detail_fits_its_card_whole() -> None:
    """The host's own cap is 4,000 characters, so a card cuts nothing it sends."""
    text = "x" * 3_960 + "\n[truncated, 1234 more characters]"
    assert len(text) <= 4_000
    assert _detail(_card(_call(text))) == text


async def test_a_detail_longer_than_a_card_says_where_it_was_cut() -> None:
    detail = _detail(_card(_call("x" * 4_001)))
    assert len(detail) == 4_000
    assert detail.endswith(" […truncated]")


def _calls(count: int, text: str) -> list[Item]:
    return [_call(text, item_id=f"call-{index}") for index in range(count)]


def _streamed_bytes(drawn: StreamedActivity) -> int:
    return len(
        json.dumps(
            [{"type": "blocks", "blocks": [block]} for block in drawn.blocks]
        ).encode()
    )


def _post(text: str) -> tuple[int, list[str]]:
    drawn = render_activity_plan(_calls(_MAX_SECTION_ITEMS, text), _turn("completed"))
    details = [_detail(task) for task in drawn.blocks[0]["tasks"][1:]]
    assert len(details) == _MAX_SECTION_ITEMS
    return len(json.dumps(drawn.blocks).encode()), details


async def test_a_post_of_full_cards_fits_whole_when_it_can() -> None:
    """A section of 4,000-character ASCII details is under the post budget as it is."""
    weight, details = _post("x" * 4_000)

    assert weight <= _MAX_POST_BYTES
    assert all(detail == "x" * 4_000 for detail in details)


async def test_a_post_of_full_cards_too_heavy_to_send_is_cut_back_to_fit() -> None:
    """In a language that costs six bytes a character, every card is cut, and says so."""
    weight, details = _post("漢" * 4_000)

    assert weight <= _MAX_POST_BYTES
    assert all(detail.endswith(" […truncated]") for detail in details)


async def test_a_stream_of_full_cards_stays_inside_its_budget() -> None:
    """Two pages of 4,000-character details, in the costliest language, still fit."""
    for text in ("x" * 4_000, "漢" * 4_000):
        drawn = render_activity_stream(
            _calls(2 * _MAX_SECTION_ITEMS, text), _turn("completed"), elapsed_seconds=90
        )

        assert _streamed_bytes(drawn) <= _MAX_STREAM_BYTES
        details = [
            _detail(task)
            for block in drawn.blocks
            if block["type"] == "plan"
            for task in block["tasks"]
            if "details" in task and task["task_id"] != "switch-session"
        ]
        assert len(details) == 2 * _MAX_SECTION_ITEMS
        assert all(detail.endswith(" […truncated]") for detail in details)


# ── The log, where a platform's log is body text ──────────────────────────────


async def test_a_multi_line_detail_is_one_line_of_the_log() -> None:
    text = (
        'Input: {"command":"psql","env":{"PGPASSWORD":"[REDACTED]"}}\n\n'
        "Output:\nconnecting to postgres://app:[REDACTED]@db/main\n  rows: 3\n"
    )

    assert _log([_call(text)]) == [
        '⌗ ✓ Ran a command — Input: {"command":"psql","env":{"PGPASSWORD":"[REDACTED]"}} '
        "Output: connecting to postgres://app:[REDACTED]@db/main rows: 3"
    ]


async def test_a_long_detail_is_cut_at_its_own_budget_and_a_remark_at_its_own() -> None:
    """A call gets a longer preview than before; what the agent said does not change."""
    call, said = _log(
        [
            _call("x" * 1_000),
            _item(itemId="said", kind="assistant-message", title="", text="y" * 1_000),
        ]
    )

    detail = call.removeprefix("⌗ ✓ Ran a command — ")
    assert len(detail) == 300
    assert detail.endswith("…")
    assert len(said.removeprefix("❝ ")) == 320


async def test_a_call_without_detail_is_drawn_as_before() -> None:
    assert _log([_call("")]) == ["⌗ ✓ Ran a command"]
    assert _log([_call("42 passed", title="Ran the tests")]) == [
        "⌗ ✓ Ran the tests — 42 passed"
    ]


async def test_the_status_line_shows_titles_never_detail() -> None:
    """The line beside a running turn is not where a call's input and output go."""
    items = [
        _item(
            itemId="call",
            kind="tool-activity",
            status="in-progress",
            title="Ran psql",
            text=f"Output:\nDB_PASSWORD={PASSWORD}\nrows: 3",
        )
    ]
    for tool_detail in (True, False):
        status = turn_status(
            items,
            _turn("running"),
            escape=_identity,
            limit=10_000,
            markup=MARKDOWN,
            tool_detail=tool_detail,
        )
        assert "rows: 3" not in status
        assert PASSWORD not in status
        assert "Output:" not in status
