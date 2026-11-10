// Checks the agent-facing side of a running docs site:
// llms.txt lists .md pages, each .md page is served as Markdown without leftover MDX/JSX,
// and (if supported) the HTML URL answers `Accept: text/markdown`.
//
// usage: bun scripts/check-md.mjs [http://localhost:3100]
const base = process.argv[2] ?? "http://localhost:3100";
let failed = 0;
const fail = (msg) => {
	failed++;
	console.log(`  FAIL ${msg}`);
};

const llms = await fetch(`${base}/llms.txt`);
if (!llms.ok) fail(`/llms.txt: ${llms.status}`);
const index = await llms.text();
const links = [...index.matchAll(/\]\(([^)]+\.md)\)/g)].map((m) => m[1]);
console.log(`/llms.txt: ${links.length} .md links`);
if (links.length === 0) fail("/llms.txt links no .md pages");

for (const link of links) {
	const res = await fetch(new URL(link, base));
	const type = res.headers.get("content-type") ?? "";
	const body = await res.text();
	const prose = body.replace(/^```[\s\S]*?^```/gm, ""); // ignore code blocks
	const problems = [];
	if (!res.ok) problems.push(`status ${res.status}`);
	if (!/markdown|text\/plain/.test(type)) problems.push(`content-type ${type}`);
	if (/<\/?[A-Z][\w.]*[\s/>]/.test(prose))
		problems.push("leftover JSX component");
	if (/^(import|export) /m.test(prose)) problems.push("leftover import/export");
	if (/\[#[\w-]+\]$/m.test(prose)) problems.push("heading id syntax");
	if (
		/\]\(\/docs[^)]*(?<!\.md)(#[^)]*)?\)/.test(
			prose.replace(/\.md#[^)]*\)/g, ".md)"),
		)
	)
		problems.push("link to an HTML docs page");
	if (!/^# /m.test(body)) problems.push("no title");
	if (problems.length) fail(`${link}: ${problems.join(", ")}`);
	else console.log(`  ok   ${link} (${body.length} bytes)`);
}

const htmlUrl = links[0]?.replace(/\.md$/, "");
if (htmlUrl) {
	const res = await fetch(new URL(htmlUrl, base), {
		headers: { Accept: "text/markdown" },
	});
	const type = res.headers.get("content-type") ?? "";
	console.log(
		`Accept: text/markdown on ${htmlUrl}: ${type.includes("markdown") ? "Markdown" : `not supported (${type})`}, Vary: ${res.headers.get("vary") ?? "-"}`,
	);
}

const full = await fetch(`${base}/llms-full.txt`);
console.log(
	`/llms-full.txt: ${full.ok ? `${(await full.text()).length} bytes` : full.status}`,
);
if (!full.ok) fail("/llms-full.txt missing");

console.log(failed ? `${failed} problem(s)` : "all good");
process.exit(failed ? 1 : 0);
