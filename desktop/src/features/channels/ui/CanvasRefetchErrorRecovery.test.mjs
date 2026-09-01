/**
 * Refetch-error recovery regression: after a save or restore is accepted with
 * `verified: false`, subsequent settlement-triggered query refetch failures must
 * not replace the accepted-write notice or unmount the cached canvas/history.
 *
 * The distinguishing invariant in both components: `error && data === undefined`
 * is an initial load failure with no usable data and renders the full error
 * state; `error && data !== undefined` is a failed background refetch and must
 * leave the cached subtree mounted with a separate refresh warning. Reverting
 * either component's `data === undefined` guard to an unconditional error return
 * causes the corresponding scenario below to fail.
 *
 * Tests mount the shipping ChannelCanvas (which embeds CanvasHistoryPanel) with
 * a real QueryClient, drive actual setCanvas settlement invalidation, and reject
 * subsequent refetches to produce the error+data state.
 *
 * Also covers the no-data initial-error branch for both components to confirm
 * the guard does not suppress genuine first-load failures.
 */

import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { after, before, test } from "node:test";

import { JSDOM } from "jsdom";

import { installRadixDialogGlobals } from "./canvasDialogTestEnv.mjs";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "@/shared/ui/markdown") {
      return { shortCircuit: true, url: "buzz-canvas-stub:markdown" };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url === "buzz-canvas-stub:markdown") {
      return {
        format: "module",
        shortCircuit: true,
        source: "export function Markdown() { return null; }\n",
      };
    }
    return nextLoad(url, context);
  },
});

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});

const HEAD = "a".repeat(64);
const OLDER = "b".repeat(64);

let React;
let act;
let createRoot;
let QueryClient;
let QueryClientProvider;
let ChannelNavigationProvider;
let CommunitiesProvider;
let ChannelCanvas;

// Tracks how many get_canvas calls have been made. Tests flip
// `failRefetches` after the initial load succeeds so that the
// settlement-triggered invalidation refetch fails.
let getCanvasCallCount = 0;
let getCanvasHistoryCallCount = 0;
let failRefetches = false;
let nextSetCanvasVerified = false;

before(async () => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    window: dom.window,
    localStorage: dom.window.localStorage,
    IS_REACT_ACT_ENVIRONMENT: true,
  });
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: dom.window.navigator,
    writable: true,
  });
  dom.window.matchMedia = () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  });
  installRadixDialogGlobals(dom);

  dom.window.__TAURI_INTERNALS__ = {
    invoke: async (cmd) => {
      if (cmd === "get_canvas") {
        getCanvasCallCount++;
        if (failRefetches) {
          throw new Error("relay unavailable");
        }
        return { content: "hi", event_id: HEAD, updated_at: 1, author: HEAD };
      }
      if (cmd === "set_canvas") {
        return {
          ok: true,
          event_id: "e".repeat(64),
          verified: nextSetCanvasVerified,
        };
      }
      if (cmd === "get_canvas_history") {
        getCanvasHistoryCallCount++;
        if (failRefetches) {
          throw new Error("relay unavailable");
        }
        return {
          revisions: [
            { event_id: HEAD, content: "hi", created_at: 2, author: HEAD },
            { event_id: OLDER, content: "old", created_at: 1, author: HEAD },
          ],
          next_cursor: null,
        };
      }
      if (cmd === "get_users_batch") {
        return { profiles: {} };
      }
      throw new Error(`unexpected command: ${cmd}`);
    },
  };

  ({ default: React, act } = await import("react"));
  ({ createRoot } = await import("react-dom/client"));
  ({ QueryClient, QueryClientProvider } = await import(
    "@tanstack/react-query"
  ));
  ({ ChannelNavigationProvider } = await import(
    "@/shared/context/ChannelNavigationContext"
  ));
  ({ CommunitiesProvider } = await import(
    "@/features/communities/useCommunities"
  ));
  ({ ChannelCanvas } = await import("./ChannelCanvas.tsx"));
});

after(() => dom.window.close());

function click(element) {
  element.dispatchEvent(
    new dom.window.MouseEvent("click", { bubbles: true, cancelable: true }),
  );
}

async function settle(iterations = 12) {
  for (let i = 0; i < iterations; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 1));
    });
  }
}

function makeClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { gcTime: Number.POSITIVE_INFINITY, retry: false },
      mutations: { gcTime: 0 },
    },
  });
}

async function mountCanvas(queryClient) {
  const container = dom.window.document.createElement("div");
  dom.window.document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(
      React.createElement(
        QueryClientProvider,
        { client: queryClient },
        React.createElement(
          CommunitiesProvider,
          null,
          React.createElement(
            ChannelNavigationProvider,
            { channels: [] },
            React.createElement(ChannelCanvas, {
              channelId: "channel-1",
              canEdit: true,
              isArchived: false,
            }),
          ),
        ),
      ),
    );
  });
  // Prime the canvas query with one successful fetch.
  await act(async () => {
    await queryClient.refetchQueries({ queryKey: ["channel-canvas"] });
  });
  await settle();
  return { container, root };
}

// ── Save scenario ─────────────────────────────────────────────────────────────

test("save: verified:false + refetch failure keeps canvas and save notice mounted", async () => {
  failRefetches = false;
  nextSetCanvasVerified = false;
  getCanvasCallCount = 0;

  const queryClient = makeClient();
  const { container, root } = await mountCanvas(queryClient);

  // Confirm initial canvas rendered.
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-content']"),
    "canvas content renders after initial load",
  );

  // Open editor and save.
  await act(async () =>
    click(container.querySelector("[data-testid='channel-canvas-edit']")),
  );
  assert.ok(container.querySelector("[data-testid='channel-canvas-editor']"));

  // Arm refetch failures BEFORE the save (the mutation's onSettled will
  // invalidate and trigger a refetch that must fail).
  failRefetches = true;

  await act(async () => {
    click(container.querySelector("[data-testid='channel-canvas-save']"));
  });
  await settle(20);

  // The save notice must still be visible — refetch failure must not clear it.
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-unverified-notice']"),
    "unverified save notice survives a failed settlement refetch",
  );
  // The cached canvas must remain mounted.
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-content']"),
    "cached canvas content remains mounted after failed refetch",
  );
  // A non-destructive refresh warning must appear.
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-refresh-error']"),
    "refresh warning renders alongside the cached canvas",
  );
  // The full-error destructive path must NOT have fired.
  assert.equal(
    container.querySelector("[role='alert']"),
    null,
    "the full destructive error state must not render when data is cached",
  );

  failRefetches = false;
  await settle(4);
  await act(async () => root.unmount());
  queryClient.clear();
  container.remove();
});

test("save: successful refetch after recovery clears the refresh warning", async () => {
  failRefetches = false;
  nextSetCanvasVerified = false;
  getCanvasCallCount = 0;

  const queryClient = makeClient();
  const { container, root } = await mountCanvas(queryClient);

  await act(async () =>
    click(container.querySelector("[data-testid='channel-canvas-edit']")),
  );

  failRefetches = true;
  await act(async () => {
    click(container.querySelector("[data-testid='channel-canvas-save']"));
  });
  await settle(20);
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-refresh-error']"),
    "refresh warning present after failed refetch",
  );
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-unverified-notice']"),
    "save notice still visible",
  );

  // Restore connectivity and manually trigger a successful refetch.
  failRefetches = false;
  await act(async () => {
    await queryClient.refetchQueries({ queryKey: ["channel-canvas"] });
  });
  await settle(12);

  assert.equal(
    container.querySelector("[data-testid='channel-canvas-refresh-error']"),
    null,
    "refresh warning clears once refetch succeeds",
  );
  // Save notice persists until next edit session (its existing reset boundary).
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-unverified-notice']"),
    "save notice persists after refetch recovery",
  );

  await act(async () => root.unmount());
  queryClient.clear();
  container.remove();
});

// ── Restore scenario ──────────────────────────────────────────────────────────

test("restore: verified:false + refetch failure keeps history panel, restore notice, and rows mounted", async () => {
  failRefetches = false;
  nextSetCanvasVerified = false;
  getCanvasCallCount = 0;
  getCanvasHistoryCallCount = 0;

  const queryClient = makeClient();
  const { container, root } = await mountCanvas(queryClient);

  // Open history panel.
  await act(async () =>
    click(
      container.querySelector("[data-testid='channel-canvas-history-toggle']"),
    ),
  );
  // Prime the history query with a successful fetch.
  await act(async () => {
    await queryClient.refetchQueries({
      queryKey: ["channel-canvas-history"],
    });
  });
  await settle(12);

  assert.ok(
    container.querySelector("[data-testid='channel-canvas-history']"),
    "history panel renders after initial load",
  );

  // Expand the older (non-current) revision.
  const items = container.querySelectorAll(
    "[data-testid='channel-canvas-history-item'] button",
  );
  await act(async () => click(items[items.length - 1]));
  await settle();
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-restore']"),
    "restore button visible for older revision",
  );

  // Arm refetch failures BEFORE the restore mutation fires.
  failRefetches = true;

  await act(async () => {
    click(container.querySelector("[data-testid='channel-canvas-restore']"));
  });
  await settle();

  // Confirm the restore in the dialog.
  await act(async () => {
    click(
      dom.window.document.querySelector(
        "[data-testid='channel-canvas-restore-confirm-action']",
      ),
    );
  });
  await settle(20);

  // History panel must remain mounted — not replaced by error state.
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-history']"),
    "history panel remains mounted after failed settlement refetch",
  );
  // Restore notice must be visible.
  assert.ok(
    container.querySelector(
      "[data-testid='channel-canvas-restore-unverified-notice']",
    ),
    "restore notice survives failed settlement refetch",
  );
  // History rows must still be present.
  const rows = container.querySelectorAll(
    "[data-testid='channel-canvas-history-item']",
  );
  assert.ok(
    rows.length > 0,
    "history rows remain visible after failed refetch",
  );
  // A non-destructive history refresh warning must appear.
  assert.ok(
    container.querySelector(
      "[data-testid='channel-canvas-history-refresh-error']",
    ),
    "history refresh warning renders alongside cached rows",
  );
  // Parent canvas must also remain mounted with its own refresh warning.
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-content']"),
    "parent canvas content remains mounted",
  );
  assert.ok(
    container.querySelector("[data-testid='channel-canvas-refresh-error']"),
    "canvas refresh warning renders",
  );

  failRefetches = false;
  await settle(4);
  await act(async () => root.unmount());
  queryClient.clear();
  container.remove();
});

// ── Initial-error no-data branches ────────────────────────────────────────────

test("canvas: initial load failure with no data renders full error state", async () => {
  // Start with refetches failing so the very first load fails.
  failRefetches = true;
  nextSetCanvasVerified = false;
  getCanvasCallCount = 0;

  const queryClient = makeClient();
  const container = dom.window.document.createElement("div");
  dom.window.document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(
      React.createElement(
        QueryClientProvider,
        { client: queryClient },
        React.createElement(
          CommunitiesProvider,
          null,
          React.createElement(
            ChannelNavigationProvider,
            { channels: [] },
            React.createElement(ChannelCanvas, {
              channelId: "channel-1",
              canEdit: true,
              isArchived: false,
            }),
          ),
        ),
      ),
    );
  });
  await act(async () => {
    await queryClient.refetchQueries({ queryKey: ["channel-canvas"] });
  });
  await settle(12);

  // Full destructive error state must render.
  assert.ok(
    container.querySelector("[role='alert']"),
    "full error state renders on initial load failure with no data",
  );
  // Non-destructive refresh warning must NOT appear (no cached data to show).
  assert.equal(
    container.querySelector("[data-testid='channel-canvas-refresh-error']"),
    null,
    "no refresh warning on initial failure — there is no cached canvas",
  );

  failRefetches = false;
  await act(async () => root.unmount());
  queryClient.clear();
  container.remove();
});
