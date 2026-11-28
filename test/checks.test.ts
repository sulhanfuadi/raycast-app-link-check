import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkAasa,
  checkAssetLinks,
  evaluateAasa,
  evaluateAssetLinks,
  normalizeDomain,
  runChecks,
} from "../src/checks";

const FP = Array(32).fill("AB").join(":");
const stub = (map: (u: string, init?: RequestInit) => Response) =>
  ((u: any, i: any) => Promise.resolve(map(String(u), i))) as typeof fetch;
const ok = (b: unknown) => new Response(JSON.stringify(b), { status: 200 });

test("normalizeDomain accepts hosts and strips scheme/path, rejects junk", () => {
  assert.equal(normalizeDomain(" https://Example.com/path "), "example.com");
  assert.equal(normalizeDomain("localhost"), undefined);
  assert.equal(normalizeDomain("exa mple.com"), undefined);
  assert.equal(normalizeDomain("a.com:8080"), undefined);
});
test("AASA: expected ID present ok, absent fail, none listed warn", () => {
  const d = { applinks: { details: [{ appIDs: ["T.com.x"] }] } };
  assert.equal(evaluateAasa(d, "T.com.x").status, "ok");
  assert.equal(evaluateAasa(d, "T.com.y").status, "fail");
  assert.equal(evaluateAasa({ applinks: { details: [] } }).status, "warn");
  assert.equal(evaluateAasa(d).status, "ok");
});
test("AASA redirect fails, bad JSON fails", async () => {
  assert.equal(
    (
      await checkAasa(
        stub(() => new Response("", { status: 301 })),
        "a.com",
      )
    ).status,
    "fail",
  );
  assert.equal(
    (
      await checkAasa(
        stub(() => new Response("<html>")),
        "a.com",
      )
    ).status,
    "fail",
  );
});
test("assetlinks: empty warn, wrong package fail, missing fingerprint fail, good ok, bad fp format warn", () => {
  const st = (pkg: string, fps: string[]) => ({
    relation: ["delegate_permission/common.handle_all_urls"],
    target: {
      namespace: "android_app",
      package_name: pkg,
      sha256_cert_fingerprints: fps,
    },
  });
  assert.equal(evaluateAssetLinks([]).status, "warn");
  assert.equal(evaluateAssetLinks([st("a.b", [FP])], "c.d").status, "fail");
  assert.equal(evaluateAssetLinks([st("a.b", [])], "a.b").status, "fail");
  assert.equal(evaluateAssetLinks([st("a.b", [FP])], "a.b").status, "ok");
  assert.equal(evaluateAssetLinks([st("a.b", ["nope"])], "a.b").status, "warn");
  assert.equal(evaluateAssetLinks({}).status, "fail");
});
test("runChecks returns an iOS and an Android row; network error is a fail row", async () => {
  const rows = await runChecks({
    domain: "a.com",
    f: stub((u) =>
      ok(u.includes("assetlinks") ? [] : { applinks: { details: [] } }),
    ),
  });
  assert.deepEqual(
    rows.map((r) => r.platform),
    ["iOS", "Android"],
  );
  const boom = (() => Promise.reject(new Error("dns"))) as typeof fetch;
  assert.ok(
    (await runChecks({ domain: "a.com", f: boom })).every(
      (r) => r.status === "fail",
    ),
  );
  assert.equal(
    (
      await checkAssetLinks(
        stub(() => new Response("", { status: 404 })),
        "a.com",
      )
    ).status,
    "fail",
  );
});

test("assetlinks redirect fails, wrong content-type warns", async () => {
  assert.equal(
    (
      await checkAssetLinks(
        stub(() => new Response("", { status: 302 })),
        "a.com",
      )
    ).status,
    "fail",
  );
  const good = [
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: {
        namespace: "android_app",
        package_name: "p.q",
        sha256_cert_fingerprints: [Array(32).fill("AB").join(":")],
      },
    },
  ];
  const r = await checkAssetLinks(
    stub(
      () =>
        new Response(JSON.stringify(good), {
          status: 200,
          headers: { "content-type": "text/html" },
        }),
    ),
    "a.com",
  );
  assert.equal(r.status, "warn");
});

const stmt = (extra: object) => ({
  relation: ["delegate_permission/common.handle_all_urls"],
  target: { namespace: "android_app", package_name: "p.q", ...extra },
});

test("assetlinks: missing or malformed package names never pass", () => {
  const stmtWithoutPackage = (extra: object) => ({
    relation: ["delegate_permission/common.handle_all_urls"],
    target: { namespace: "android_app", ...extra },
  });
  assert.equal(
    evaluateAssetLinks([
      stmtWithoutPackage({ sha256_cert_fingerprints: [FP] }),
    ]).status,
    "warn",
  );
  assert.equal(
    evaluateAssetLinks([
      { ...stmt({ sha256_cert_fingerprints: [FP] }), target: { namespace: "android_app", package_name: "", sha256_cert_fingerprints: [FP] } },
    ]).status,
    "warn",
  );
  assert.equal(
    evaluateAssetLinks([
      { ...stmt({ sha256_cert_fingerprints: [FP] }), target: { namespace: "android_app", package_name: 42, sha256_cert_fingerprints: [FP] } },
    ]).status,
    "warn",
  );
  const missing = evaluateAssetLinks([
    stmtWithoutPackage({ sha256_cert_fingerprints: [FP] }),
  ]);
  assert.equal(missing.status, "warn");
  assert.equal(missing.detail.includes("package_name"), true);
});

test("assetlinks: missing, empty or string fingerprints do not pass", () => {
  assert.equal(evaluateAssetLinks([stmt({})]).status, "warn");
  assert.equal(
    evaluateAssetLinks([stmt({ sha256_cert_fingerprints: [] })]).status,
    "warn",
  );
  assert.equal(
    evaluateAssetLinks([stmt({ sha256_cert_fingerprints: FP })]).status,
    "warn",
  );
  assert.equal(
    evaluateAssetLinks([stmt({ sha256_cert_fingerprints: [FP] })]).status,
    "ok",
  );
  assert.equal(
    evaluateAssetLinks(
      [stmt({ sha256_cert_fingerprints: FP })],
      "p.q",
    ).detail.includes("fingerprint"),
    true,
  );
});
test("AASA: non-string or empty app IDs warn", () => {
  assert.equal(
    evaluateAasa({ applinks: { details: [{ appIDs: [null] }] } }).status,
    "warn",
  );
  assert.equal(
    evaluateAasa({ applinks: { details: [{ appIDs: ["T.a.b", 5] }] } }).status,
    "warn",
  );
  assert.equal(
    evaluateAasa({ applinks: { details: [{ appIDs: [" "] }] } }).status,
    "warn",
  );
});
test("assetlinks: content type must be exactly application/json", async () => {
  const body = JSON.stringify([stmt({ sha256_cert_fingerprints: [FP] })]);
  const ct = (v: string) =>
    stub(
      () => new Response(body, { status: 200, headers: { "content-type": v } }),
    );
  assert.equal(
    (await checkAssetLinks(ct("application/json; charset=utf-8"), "a.com"))
      .status,
    "ok",
  );
  assert.equal(
    (await checkAssetLinks(ct("Application/JSON"), "a.com")).status,
    "ok",
  );
  assert.equal(
    (await checkAssetLinks(ct("application/jsonp"), "a.com")).status,
    "warn",
  );
  assert.equal(
    (await checkAssetLinks(ct("text/application/json"), "a.com")).status,
    "warn",
  );
});
test("oversized response fails and stops reading", async () => {
  let pulled = 0;
  const big = new ReadableStream<Uint8Array>({
    pull(c) {
      pulled++;
      c.enqueue(new Uint8Array(64 * 1024));
      if (pulled > 1000) c.close();
    },
  });
  const r = await checkAasa(
    stub(() => new Response(big, { status: 200 })),
    "a.com",
  );
  assert.equal(r.status, "fail");
  assert.ok(r.detail.includes("larger"));
  assert.ok(pulled < 20);
});

test("a UTF-8 byte-order mark does not break JSON parsing", async () => {
  const body = new Uint8Array([
    0xef,
    0xbb,
    0xbf,
    ...new TextEncoder().encode(
      JSON.stringify({ applinks: { details: [{ appIDs: ["T.a.b"] }] } }),
    ),
  ]);
  const r = await checkAasa(
    stub(() => new Response(body, { status: 200 })),
    "a.com",
  );
  assert.equal(r.status, "ok");
});
