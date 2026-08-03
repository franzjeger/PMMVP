// Tests for the bookmark reconciler.
//
//     node extension/test/bookmarks.test.mjs
//
// This is the only code in Arca that can destroy something the user cannot get
// back from the vault: bookmarks live in the browser, and a bad push-out empties
// the bookmark bar in every browser at once. The guards against that are the
// point of this file, so they are tested against the real module rather than a
// description of it.
import assert from "node:assert/strict";
import { flatten, plan, apply } from "../chromium/bookmarks.js";

let pass = 0;
const check = (name, got, want) => {
  assert.deepEqual(got, want, `${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  console.log(`  ok  ${name}`);
  pass++;
};

const bm = (folder, url) => ({ folder, url, title: url, id: `${folder}|${url}` });

console.log("\nFlattening a browser tree");
{
  // The real shape: root ids 1/2/3, localised names, nested folders.
  const roots = [
    {
      id: "1",
      title: "Bokmerkelinje",
      children: [
        { id: "10", title: "Sybr", url: "https://sybr.no" },
        {
          id: "11",
          title: "Arbeid",
          children: [{ id: "12", title: "RMM", url: "https://rmm.example" }],
        },
        { id: "13", title: "bad", url: "javascript:alert(1)" },
      ],
    },
    {
      id: "2",
      title: "Andre bokmerker",
      children: [{ id: "20", title: "Later", url: "https://later.example" }],
    },
  ];
  const flat = flatten(roots);
  // The bar's own name is localised and must never enter a path — that is why
  // the roots are mapped by id and not by title.
  check("bar entries sit at the top level", flat.find((b) => b.title === "Sybr").folder, "");
  check("nested folders become paths", flat.find((b) => b.title === "RMM").folder, "Arbeid");
  check("the other root keeps a stable name", flat.find((b) => b.title === "Later").folder, "Other");
  check("bookmarklets are dropped", flat.some((b) => b.url.startsWith("javascript:")), false);
}

console.log("\nAdditions need no permission and are never refused");
{
  const current = [bm("", "https://a.example")];
  const master = [bm("", "https://a.example"), bm("Arbeid", "https://b.example")];
  const p = plan(current, master, { deletions: false });
  check("adds what is missing", p.additions.map((b) => b.url), ["https://b.example"]);
  check("removes nothing without deletions", p.removals, []);
}

console.log("\nAn empty master never clears the browser");
{
  // A locked vault, a failed read, or an import that has not run yet all look
  // exactly like "Arca has no bookmarks" from here. None of them mean "delete
  // everything", and treating them that way loses the bar in every browser.
  const current = [bm("", "https://a.example"), bm("", "https://b.example")];
  const p = plan(current, [], { deletions: true, confirmed: true });
  check("removals are refused outright", p.removals, []);
  check("and the reason says why", /empty/.test(p.refused), true);
}

console.log("\nA large deletion pass needs a human");
{
  const current = Array.from({ length: 100 }, (_, i) => bm("", `https://x${i}.example`));
  // Arca knows about 50 of them; the other 50 would go.
  const master = current.slice(0, 50);
  const p = plan(current, master, { deletions: true });
  check("nothing is removed unconfirmed", p.removals, []);
  check("the count is reported so it can be shown", p.pendingRemovals, 50);
  check("the refusal names the numbers", /50 of 100/.test(p.refused), true);

  const confirmed = plan(current, master, { deletions: true, confirmed: true });
  check("confirming lets it through", confirmed.removals.length, 50);
}

console.log("\nOrdinary tidying is not blocked");
{
  // Removing a handful is normal use and must not need a dialog every time,
  // or the confirmation becomes something people click through blindly.
  const current = Array.from({ length: 100 }, (_, i) => bm("", `https://x${i}.example`));
  const master = current.slice(0, 95);
  const p = plan(current, master, { deletions: true });
  check("five removals go through unattended", p.removals.length, 5);
  check("with no refusal", p.refused, null);
}

console.log("\nPolicy-managed bookmarks are never touched");
{
  const managed = { ...bm("", "https://corp.example"), unmodifiable: "managed" };
  const current = [managed, bm("", "https://mine.example")];
  const p = plan(current, [bm("", "https://mine.example")], {
    deletions: true,
    confirmed: true,
  });
  check("a managed entry is not proposed for removal", p.removals, []);
}

console.log("\nThe same page filed twice stays two bookmarks");
{
  // Identity is folder + url on purpose: someone who filed a page under both
  // "Arbeid" and "Privat" meant to.
  const current = [bm("Arbeid", "https://p.example")];
  const master = [bm("Arbeid", "https://p.example"), bm("Privat", "https://p.example")];
  const p = plan(current, master, { deletions: true, confirmed: true });
  check("the second filing is an addition", p.additions.length, 1);
  check("and the first is not a removal", p.removals, []);
}

console.log("\napply() survives a node the browser refuses");
{
  // One bookmark in a managed folder must not abort the other additions.
  const api = {
    bookmarks: {
      getTree: async () => [{ id: "0", children: [{ id: "1", children: [] }] }],
      getChildren: async () => [],
      create: async ({ url }) => {
        if (url === "https://boom.example") throw new Error("managed");
        return { id: `n${url}` };
      },
      remove: async () => {},
    },
  };
  const res = await apply(api, [
    bm("", "https://ok1.example"),
    bm("", "https://boom.example"),
    bm("", "https://ok2.example"),
  ]);
  check("the good ones still landed", res.added, 2);
}

console.log(`\n${pass} checks passed\n`);
