// Builds the site into dist/: every docs page as HTML and as Markdown, the home page,
// llms.txt and llms-full.txt, the stylesheet (Tailwind), site.js and the search index
// (Pagefind). `bun run build`; `bun run dev` runs it again on every change.
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { mdxComponents } from "@/components/mdx";
import { schema } from "@/lib/config-markdown.mjs";
import { DocsPage } from "@/pages/docs";
import { HomePage } from "@/pages/home";
import { NotFoundPage } from "@/pages/not-found";
import { loadDocs } from "./content";
import { markdownComponents, pageMarkdown } from "./markdown";
import { compilePage } from "./mdx";

const root = join(import.meta.dir, "..");
const dist = join(root, "dist");
const dev = Bun.env.ANSAGE_DEV === "1";
const started = performance.now();

function write(path: string, content: string) {
	const file = join(dist, path);
	mkdirSync(dirname(file), { recursive: true });
	writeFileSync(file, content);
}

const html = (element: ReactElement) =>
	`<!doctype html>${renderToStaticMarkup(element)}`;

async function run(cmd: string[]) {
	const proc = Bun.spawn(cmd, { cwd: root, stdout: "pipe", stderr: "pipe" });
	const [out, err, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	if (code !== 0) throw new Error(`${cmd.join(" ")} failed:\n${out}${err}`);
	return out;
}

// The HTML and the Markdown side must know the same components.
const htmlComponents = Object.keys(mdxComponents).filter((k) =>
	/^[A-Z]/.test(k),
);
const missing = htmlComponents
	.filter((k) => !markdownComponents.includes(k))
	.concat(markdownComponents.filter((k) => !htmlComponents.includes(k)));
if (missing.length) {
	throw new Error(
		`components without both forms (HTML and Markdown): ${missing}`,
	);
}

await run(["bun", "scripts/extract-config.mjs"]);
rmSync(dist, { recursive: true, force: true });

// docs: HTML at /docs/x/index.html, Markdown at /docs/x.md
const docs = loadDocs();
const markdown: string[] = [];
for (const page of docs.pages) {
	const { Content, toc } = await compilePage(page.body);
	if (page.body.includes("<ConfigReference")) {
		// its headings come from the schema, not from the MDX
		for (const s of schema.sections)
			toc.push({ depth: 2, id: s.id, text: s.title });
	}
	write(
		`${page.url}/index.html`,
		html(
			<DocsPage
				docs={docs}
				page={page}
				Content={Content}
				toc={toc}
				dev={dev}
			/>,
		),
	);
	const md = pageMarkdown(page);
	write(`${page.url}.md`, md);
	markdown.push(md);
}

write("index.html", html(<HomePage dev={dev} />));
write("404.html", html(<NotFoundPage dev={dev} />));

// for agents: an index of the .md pages, and all pages in one file
const entry = (p: (typeof docs.pages)[number]) =>
	`- [${p.title}](${p.url}.md)${p.description ? `: ${p.description}` : ""}`;
write(
	"llms.txt",
	`# ansage

> BGP router for Linux, written in Rust, growing into a replacement for BIRD and FRR. Safe by default: a new config sends only your own prefixes and accepts nothing. Today it announces your own prefixes (anycast, a VPS's IPv6 range), passes routes on to customers with roles and filters, and installs learned routes into the Linux kernel.

Every page is available as Markdown: append \`.md\` to its URL, or send \`Accept: text/markdown\`.
All pages in one file: /llms-full.txt

${entry(docs.intro)}

${docs.sections.map((s) => `## ${s.title}\n\n${s.pages.map(entry).join("\n")}`).join("\n\n")}
`,
);
write("llms-full.txt", `${markdown.join("\n\n")}`);

// the logo as favicon (same drawing as components/logo.tsx)
write(
	"favicon.svg",
	`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none"><rect width="128" height="128" rx="32" fill="#EDB24D"/><g stroke="black" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"><path d="M75.5785 69.0506C80.8804 78.2338 77.734 89.9763 68.5508 95.2783C59.3676 100.58 47.625 97.4338 42.3231 88.2506C37.0212 79.0674 40.1676 67.3248 49.3508 62.0229C58.534 56.721 70.2765 59.8674 75.5785 69.0506Z"/><path d="M21.638 78.0229L67.826 51.3562M15.6667 74.0803L22.0667 85.1655"/></g><path d="M62.9214 49.2612C74.8826 41.5342 83.0821 30.8472 87.5197 17.2C96.8687 26.993 103.447 38.3861 107.253 51.3791C93.2154 48.3986 79.8604 50.156 67.188 56.6513L62.9214 49.2612Z" fill="black"/></svg>\n`,
);

// fonts, self-hosted (latin, variable weight)
for (const [pkg, file] of [
	["geist", "geist-latin-wght-normal.woff2"],
	["geist-mono", "geist-mono-latin-wght-normal.woff2"],
]) {
	cpSync(
		join(root, "node_modules/@fontsource-variable", pkg, "files", file),
		join(dist, "assets/fonts", file),
	);
}

await run([
	"bunx",
	"tailwindcss",
	"-i",
	"src/styles.css",
	"-o",
	"dist/assets/style.css",
	...(dev ? [] : ["--minify"]),
]);

const client = await Bun.build({
	entrypoints: [join(root, "src/client/site.ts")],
	outdir: join(dist, "assets"),
	minify: !dev,
	target: "browser",
});
if (!client.success) throw new AggregateError(client.logs, "site.js failed");

// search index of the docs (only <article data-pagefind-body>)
await run(["bunx", "pagefind", "--site", "dist", "--quiet"]);

console.log(
	`built ${docs.pages.length} docs pages in ${Math.round(performance.now() - started)} ms`,
);
