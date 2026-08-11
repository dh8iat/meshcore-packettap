#!/usr/bin/env python3
"""Generic asynchronous QuestDB backend shared by all MeshCore tools."""

from __future__ import annotations

import asyncio
import re
import time
import urllib.parse
import urllib.request
from typing import Any

from questdb.ingress import Sender, TimestampNanos


DEFAULT_QUESTDB_HOST = "localhost"
DEFAULT_QUESTDB_PORT = 9000
DEFAULT_FLUSH_INTERVAL_SECONDS = 2.0
DEFAULT_FLUSH_ROW_THRESHOLD = 200
DEFAULT_QUEUE_MAXSIZE = 10000
DEFAULT_ERROR_LOG_INTERVAL_SECONDS = 15.0

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_writer: QuestDBWriter | None = None


def clean_db_text(value: Any, max_len: int = 500) -> str | None:
    """Sanitize text before it reaches QuestDB line protocol."""
    if value is None:
        return None

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")

    text = ANSI_RE.sub("", str(value))
    text = "".join(
        character
        for character in text
        if character.isprintable() and character not in "\r\n\t"
    ).strip()

    return text[:max_len] or None


class QuestDBWriter:
    """Buffered asynchronous QuestDB ILP-over-HTTP writer."""

    def __init__(
        self,
        host: str = DEFAULT_QUESTDB_HOST,
        port: int = DEFAULT_QUESTDB_PORT,
        *,
        enabled: bool = True,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        flush_row_threshold: int = DEFAULT_FLUSH_ROW_THRESHOLD,
        queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        error_log_interval: float = DEFAULT_ERROR_LOG_INTERVAL_SECONDS,
    ) -> None:
        self.host = host
        self.port = port
        self.enabled = enabled
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=queue_maxsize
        )
        self.flush_interval = flush_interval
        self.flush_row_threshold = flush_row_threshold
        self.error_log_interval = error_log_interval
        self.running = True
        self.last_error_log = 0.0

    async def enqueue(
        self,
        table_name: str,
        ts_seconds: int | float | None,
        symbols: dict[str, Any],
        columns: dict[str, Any],
    ) -> None:
        if not self.enabled or ts_seconds is None:
            return

        clean_symbols: dict[str, str] = {}
        for key, value in symbols.items():
            value_str = clean_db_text(value, max_len=200)
            if value_str is not None:
                clean_symbols[key] = value_str

        clean_columns: dict[str, Any] = {}
        for key, value in columns.items():
            if value is None:
                continue
            if isinstance(value, str):
                value = clean_db_text(value, max_len=2000)
                if value is None:
                    continue
            clean_columns[key] = value

        # Backpressure is safer than dropping database rows.
        await self.queue.put(
            {
                "type": "row",
                "table_name": table_name,
                "ts_seconds": ts_seconds,
                "symbols": clean_symbols,
                "columns": clean_columns,
            }
        )

    async def request_flush(self) -> None:
        """Request a flush without waiting for its completion."""
        await self.queue.put({"type": "flush", "waiter": None})

    async def flush(self) -> None:
        """Wait until all rows queued before this call are in QuestDB."""
        if not self.enabled:
            return

        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[None] = loop.create_future()

        await self.queue.put(
            {
                "type": "flush",
                "waiter": waiter,
            }
        )
        await waiter

    def _send_batch_sync(self, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return

        with Sender.from_conf(
            f"http::addr={self.host}:{self.port};"
        ) as sender:
            for item in batch:
                sender.row(
                    item["table_name"],
                    symbols=item["symbols"],
                    columns=item["columns"],
                    at=TimestampNanos(
                        int(item["ts_seconds"]) * 1_000_000_000
                    ),
                )
            sender.flush()

    async def _send_batch(self, batch: list[dict[str, Any]]) -> None:
        await asyncio.to_thread(self._send_batch_sync, batch)

    async def run(self) -> None:
        batch: list[dict[str, Any]] = []
        flush_waiters: list[asyncio.Future[None]] = []
        last_batch_time = time.monotonic()
        backoff = 1
        retry_pending = False

        def resolve_flush_waiters() -> None:
            while flush_waiters:
                waiter = flush_waiters.pop(0)
                if not waiter.done():
                    waiter.set_result(None)

        while self.running or not self.queue.empty() or batch:
            should_flush = retry_pending

            if not retry_pending:
                timeout = max(
                    0.1,
                    self.flush_interval
                    - (time.monotonic() - last_batch_time),
                )

                try:
                    item = await asyncio.wait_for(
                        self.queue.get(),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    item = None

                if item is not None:
                    if item["type"] == "row":
                        batch.append(item)
                        if len(batch) >= self.flush_row_threshold:
                            should_flush = True

                    elif item["type"] == "flush":
                        waiter = item.get("waiter")
                        if waiter is not None:
                            flush_waiters.append(waiter)

                        if batch:
                            should_flush = True
                        else:
                            # Everything before this barrier was already
                            # committed by an earlier successful flush.
                            resolve_flush_waiters()

                if (
                    batch
                    and time.monotonic() - last_batch_time
                    >= self.flush_interval
                ):
                    should_flush = True

            if not should_flush or not batch:
                continue

            try:
                await self._send_batch(batch)

            except Exception as exc:
                now = time.monotonic()
                if now - self.last_error_log >= self.error_log_interval:
                    print(
                        "[DB] Schreibfehler, Batch bleibt erhalten "
                        "und wird erneut versucht: "
                        f"{exc}"
                    )
                    self.last_error_log = now

                # Do not consume more queue entries until this batch has been
                # accepted. This preserves ordering across flush barriers.
                retry_pending = True
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            # sender.flush() succeeded.
            batch.clear()
            last_batch_time = time.monotonic()
            backoff = 1
            retry_pending = False
            resolve_flush_waiters()

        resolve_flush_waiters()

    async def stop(self) -> None:
        """Commit queued rows before stopping the writer."""
        if self.enabled:
            await self.flush()
        self.running = False


def configure_writer(writer: QuestDBWriter | None) -> None:
    global _writer
    _writer = writer


def get_writer() -> QuestDBWriter | None:
    return _writer


async def write_row(
    table_name: str,
    ts_seconds: int | float | None,
    symbols: dict[str, Any],
    columns: dict[str, Any],
) -> None:
    if _writer is None:
        return
    await _writer.enqueue(table_name, ts_seconds, symbols, columns)


def execute_sql(
    sql: str,
    *,
    host: str = DEFAULT_QUESTDB_HOST,
    port: int = DEFAULT_QUESTDB_PORT,
    enabled: bool = True,
) -> bool:
    if not enabled:
        return False

    try:
        params = urllib.parse.urlencode({"query": sql})
        url = f"http://{host}:{port}/exec?{params}"
        with urllib.request.urlopen(url, timeout=10) as response:
            response.read()
        return True
    except Exception as exc:
        print(f"[QuestDB SQL] Fehler bei '{sql}': {exc}")
        return False


async def execute_sql_async(
    sql: str,
    *,
    host: str = DEFAULT_QUESTDB_HOST,
    port: int = DEFAULT_QUESTDB_PORT,
    enabled: bool = True,
) -> bool:
    return await asyncio.to_thread(
        execute_sql,
        sql,
        host=host,
        port=port,
        enabled=enabled,
    )
