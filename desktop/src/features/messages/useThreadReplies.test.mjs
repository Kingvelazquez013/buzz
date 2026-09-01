/**
 * Behavioral tests for loadThreadReplies / useThreadReplies validation contract.
 *
 * These tests exercise the real fetch logic and terminal-policy paths through
 * an injected fake fetcher — no Tauri bridge required. Each test is
 * load-bearing: removing the throw in loadThreadReplies OR removing the
 * exhaustion-set check causes a specific test to fail.
 *
 * Hook-level tests (mounted-thread target change and exhaustion terminal state)
 * use a real QueryClientProvider and renderHook so mutations to the production
 * wiring — the useEffect invalidation and the query-fn exhaustion write —
 * turn the suite red.
 */

import assert from "node:assert/strict";
import { mock } from "node:test";
import test from "node:test";
import { registerHooks } from "node:module";

import { JSDOM } from "jsdom";

// ── Tauri stub ────────────────────────────────────────────────────────────────
// Stub @/shared/api/tauri before any module that imports it loads.
// Hook-level tests set globalThis.__tauriGetThreadReplies before each run;
// the stub delegates to that global so tests control the fetcher without
// changing the production hook signature.

globalThis.__tauriGetThreadReplies = async () => ({
  events: [],
  nextCursor: null,
});

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "@/shared/api/tauri") {
      return { shortCircuit: true, url: "buzz-thread-stub:tauri" };
    }
    if (specifier.startsWith("buzz-thread-stub:")) {
      return { shortCircuit: true, url: specifier };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url === "buzz-thread-stub:tauri") {
      return {
        format: "module",
        shortCircuit: true,
        // Delegate to test-controlled global so each hook test can swap the
        // fetcher without reloading the cached module.
        source: `
export async function getThreadReplies(rootId, channelId, options) {
  return globalThis.__tauriGetThreadReplies(rootId, channelId, options);
}
export default {};
`,
      };
    }
    return nextLoad(url, context);
  },
});

// ── DOM setup ─────────────────────────────────────────────────────────────────

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

Object.assign(globalThis, {
  IS_REACT_ACT_ENVIRONMENT: true,
  document: dom.window.document,
  HTMLElement: dom.window.HTMLElement,
  window: dom.window,
});

// ── Fake event builder ────────────────────────────────────────────────────────

let seq = 0;
function fakeEvent(id) {
  return {
    id,
    pubkey: "a".repeat(64),
    kind: 9,
    created_at: ++seq,
    content: "test",
    tags: [],
    sig: "sig",
  };
}

function singlePage(events) {
  return { events, nextCursor: null };
}

// ── Fake QueryClient (for loadThreadReplies unit tests) ───────────────────────

function makeQueryClient(initial = undefined) {
  let store = initial;
  return {
    getQueryData: () => store,
    setQueryData: (_key, value) => {
      store = value;
    },
    invalidateQueries: () => Promise.resolve(),
  };
}

// ── Test: throws ThreadExpectedEventMissingError when target is absent ────────
//
// Load-bearing: if the `throw new ThreadExpectedEventMissingError(...)` line in
// loadThreadReplies is removed, this test FAILS because no error is thrown.

test("loadThreadReplies throws ThreadExpectedEventMissingError when expected event is absent", async () => {
  const { loadThreadReplies, ThreadExpectedEventMissingError } = await import(
    "./useThreadReplies.ts"
  );

  const qc = makeQueryClient();
  const reply = fakeEvent("reply-1");
  const fetcher = async () => singlePage([reply]);

  await assert.rejects(
    () =>
      loadThreadReplies(
        qc,
        "chan-1",
        "root-1",
        "evt-missing",
        new Set(),
        fetcher,
      ),
    (err) => {
      assert.ok(
        err instanceof ThreadExpectedEventMissingError,
        `Expected ThreadExpectedEventMissingError, got ${err.constructor.name}`,
      );
      assert.equal(err.expectedEventId, "evt-missing");
      return true;
    },
  );
});

// ── Test: does NOT throw when expected event is present ───────────────────────

test("loadThreadReplies resolves normally when expected event is present", async () => {
  const { loadThreadReplies } = await import("./useThreadReplies.ts");

  const qc = makeQueryClient();
  const target = fakeEvent("evt-present");
  const fetcher = async () => singlePage([target]);

  const result = await loadThreadReplies(
    qc,
    "chan-2",
    "root-2",
    "evt-present",
    new Set(),
    fetcher,
  );

  assert.ok(
    result.some((e) => e.id === "evt-present"),
    "result must contain the expected event",
  );
});

// ── Test: exhaustedTargets suppresses throw — returns available replies ────────
//
// Load-bearing: if the `exhaustedTargets?.has(expectedEventId)` guard is removed
// from loadThreadReplies, this test FAILS because the function throws instead of
// resolving.

test("loadThreadReplies returns fetched replies when target is in exhaustedTargets", async () => {
  const { loadThreadReplies } = await import("./useThreadReplies.ts");

  const qc = makeQueryClient();
  const reply = fakeEvent("reply-2");
  const fetcher = async () => singlePage([reply]);
  const exhausted = new Set(["missing-target"]);

  const result = await loadThreadReplies(
    qc,
    "chan-3",
    "root-3",
    "missing-target",
    exhausted,
    fetcher,
  );

  assert.ok(Array.isArray(result), "must return an array");
  assert.ok(
    result.some((e) => e.id === "reply-2"),
    "must include fetched replies",
  );
});

// ── Test: no expectedEventId — always resolves without throw ─────────────────

test("loadThreadReplies resolves normally with no expectedEventId", async () => {
  const { loadThreadReplies } = await import("./useThreadReplies.ts");

  const qc = makeQueryClient();
  const reply = fakeEvent("reply-3");
  const fetcher = async () => singlePage([reply]);

  const result = await loadThreadReplies(
    qc,
    "chan-4",
    "root-4",
    null,
    new Set(),
    fetcher,
  );

  assert.ok(result.some((e) => e.id === "reply-3"));
});

// ── Test: multi-page fetch assembles results from all pages ──────────────────

test("loadThreadReplies aggregates events across multiple pages", async () => {
  const { loadThreadReplies } = await import("./useThreadReplies.ts");

  const qc = makeQueryClient();
  const page1Events = [fakeEvent("p1-a"), fakeEvent("p1-b")];
  const page2Events = [fakeEvent("p2-a"), fakeEvent("p2-b")];
  let calls = 0;
  const fetcher = async (_rootId, _channelId, { cursor }) => {
    calls += 1;
    if (cursor === null) {
      return {
        events: page1Events,
        nextCursor: { createdAt: 1, eventId: "p1-b" },
      };
    }
    return singlePage(page2Events);
  };

  const result = await loadThreadReplies(
    qc,
    "chan-5",
    "root-5",
    null,
    new Set(),
    fetcher,
  );

  assert.equal(calls, 2, "fetcher must be called for each page");
  const ids = new Set(result.map((e) => e.id));
  for (const evt of [...page1Events, ...page2Events]) {
    assert.ok(ids.has(evt.id), `result must include ${evt.id}`);
  }
});

// ── Test: query-fn writes exhaustion on the terminal attempt ──────────────────
//
// Load-bearing for the query-fn exhaustion write in useThreadReplies.
//
// The query-fn adds expectedEventId to exhaustedTargetsRef when attemptCount
// reaches the threshold (>= 3). loadThreadReplies then sees the target in
// exhaustedTargets and returns data instead of throwing. If the exhaustion
// write (`exhaustedTargetsRef.current.add(expectedEventId)`) is removed from
// the query-fn, the terminal attempt still throws and the hook stays in error.
//
// This test exercises the complete production path: real QueryClientProvider,
// real useThreadReplies hook, fake fetcher via globalThis stub, timer-driven
// backoff (retry: 3, retryDelay 1s/2s/4s). After the two retries, attempt 3
// writes exhaustion and loadThreadReplies resolves data synchronously.

test("useThreadReplies resolves to data after exhausting missing-event retries", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });

  let queryClient;
  let unmount;
  let cleanup;

  try {
    const imported = await import("@testing-library/react");
    const act = imported.act;
    cleanup = imported.cleanup;
    const renderHook = imported.renderHook;
    const { createElement } = await import("react");
    const { QueryClient, QueryClientProvider } = await import(
      "@tanstack/react-query"
    );
    const { useThreadReplies } = await import("./useThreadReplies.ts");

    const reply = fakeEvent("reply-exhaustion");
    // Fetcher returns a reply but never the expected event — permanently absent.
    globalThis.__tauriGetThreadReplies = async () => singlePage([reply]);

    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const channel = { id: "chan-ex", channelType: "group" };
    const wrapper = ({ children }) =>
      createElement(QueryClientProvider, { client: queryClient }, children);

    const hook = renderHook(
      () => useThreadReplies(channel, "root-ex", "evt-permanently-absent"),
      { wrapper },
    );
    unmount = hook.unmount;
    const { result } = hook;

    // Drive through the two backoff delays for attempts 1 and 2.
    // Attempt 1 throws → retryDelay 1s. Attempt 2 throws → retryDelay 2s.
    // Attempt 3 writes exhaustion pre-fetch → loadThreadReplies returns data.
    // Tick 5s per iteration (covers each delay); flush microtasks between
    // ticks so React and TanStack Query advance their state machines.
    for (let i = 0; i < 4; i++) {
      mock.timers.tick(5_000);
      await act(async () => {
        await new Promise((resolve) => setImmediate(resolve));
      });
    }

    // After the terminal attempt the query must be in success (data) state.
    assert.ok(
      !result.current.isError,
      `hook must not be in error state after exhaustion (isError=${result.current.isError})`,
    );
    assert.ok(
      Array.isArray(result.current.data),
      `hook must expose reply data after exhaustion (data=${JSON.stringify(result.current.data)})`,
    );
    assert.ok(
      result.current.data?.some((e) => e.id === reply.id),
      "data must include the fetched replies rather than being empty or errored",
    );
  } finally {
    // Always dispose — a failure before this point must not leak timers,
    // mounted hooks, or QueryClient cache timers that hold the event loop.
    try {
      unmount?.();
    } catch (_) {}
    try {
      cleanup?.();
    } catch (_) {}
    try {
      queryClient?.clear();
    } catch (_) {}
    mock.timers.reset();
  }
});

// ── Test: mounted-thread target change triggers invalidation ──────────────────
//
// Load-bearing for the useEffect invalidation seam in useThreadReplies.
//
// When expectedEventId changes from null to a non-null value while the same
// thread root is already mounted and the query key is constant, the production
// useEffect calls queryClient.invalidateQueries, triggering a second fetch. If
// that invalidateQueries call is removed from the useEffect, fetchCount stays
// at 1 and this test FAILS.
//
// Also load-bearing for the ChannelScreen wiring: the source assertion verifies
// that ChannelScreen.tsx passes threadScrollTargetId as the third argument to
// useThreadReplies. Removing that argument fails the source check, catching the
// exact bypass that allowed notification routing to skip the missing-event check.

test("useThreadReplies invalidates when expectedEventId changes on settled query", async () => {
  let queryClient;
  let unmount;
  let cleanup;
  try {
    const imported = await import("@testing-library/react");
    const act = imported.act;
    cleanup = imported.cleanup;
    const renderHook = imported.renderHook;
    const { createElement } = await import("react");
    const { QueryClient, QueryClientProvider } = await import(
      "@tanstack/react-query"
    );
    const { useThreadReplies } = await import("./useThreadReplies.ts");
    const { readFile } = await import("node:fs/promises");

    let fetchCount = 0;
    globalThis.__tauriGetThreadReplies = async () => {
      fetchCount += 1;
      return singlePage([fakeEvent(`reply-ch-${fetchCount}`)]);
    };

    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, retryDelay: 0 } },
    });
    const channel = { id: "chan-hook", channelType: "group" };
    const wrapper = ({ children }) =>
      createElement(QueryClientProvider, { client: queryClient }, children);

    const hook = renderHook(
      ({ expectedEventId }) =>
        useThreadReplies(channel, "root-hook", expectedEventId),
      { wrapper, initialProps: { expectedEventId: null } },
    );
    unmount = hook.unmount;
    const { rerender } = hook;

    // Wait for the initial fetch to settle.
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    const afterFirstFetch = fetchCount;
    assert.ok(afterFirstFetch >= 1, "initial fetch must have occurred");

    // Change expectedEventId to a non-null value — the useEffect must invalidate
    // and trigger a second fetch.
    await act(async () => {
      rerender({ expectedEventId: "evt-target" });
    });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    assert.ok(
      fetchCount > afterFirstFetch,
      `expectedEventId change must trigger an invalidation fetch ` +
        `(fetchCount=${fetchCount}, afterFirstFetch=${afterFirstFetch})`,
    );

    // ── ChannelScreen wiring assertion ────────────────────────────────────────
    // Fails if ChannelScreen stops passing threadScrollTargetId as the third
    // argument to useThreadReplies.
    const channelScreenSource = await readFile(
      new URL("../channels/ui/ChannelScreen.tsx", import.meta.url),
      "utf8",
    );
    assert.match(
      channelScreenSource,
      /useThreadReplies\s*\([^)]*threadScrollTargetId/s,
      "ChannelScreen.tsx must pass threadScrollTargetId as the third argument to useThreadReplies",
    );
  } finally {
    // Always dispose — a failure before this point must not leak mounted
    // hooks or QueryClient cache timers (gcTime: 1h) that hold the event loop.
    try {
      unmount?.();
    } catch (_) {}
    try {
      cleanup?.();
    } catch (_) {}
    try {
      queryClient?.clear();
    } catch (_) {}
  }
});

// ── Test: thread aux closure is not fetched (anti-regression) ─────────────────

test("thread replies trust the relay-provided aux closure", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(
    new URL("./useThreadReplies.ts", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(
    source,
    /withThreadAux|fetchStructuralAuxForMessages|fetchAuxEventsByReference/,
  );
  assert.match(source, /replies\.push\(\.\.\.response\.events\)/);
});
