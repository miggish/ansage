// Reads the docs from the repo's docs/ folder (like vercel/next.js): number prefixes set the
// order (03-guides/05-drain.mdx) and are left out of URLs and names (/docs/guides/drain).
// A top-level folder is a sidebar section, named after the folder; an index.mdx in it can set
// another title.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export const docsDir = join(import.meta.dir, "../../docs");

export interface Page {
	/** /docs/guides/drain */
	url: string;
	/** path inside docs/, e.g. 03-guides/05-drain.mdx (for "Edit on GitHub") */
	file: string;
	title: string;
	description: string;
	/** the MDX without its frontmatter */
	body: string;
	section?: string;
}

export interface Section {
	title: string;
	pages: Page[];
}

export interface Docs {
	/** every page in sidebar order, the introduction first */
	pages: Page[];
	/** the introduction (docs/index.mdx), then the sections */
	intro: Page;
	sections: Section[];
}

const orderPrefix = /^\d+-/;

/** "03-guides" -> "guides" */
const stripOrder = (name: string) => name.replace(orderPrefix, "");

/** "getting-started" -> "Getting started" */
function sectionTitle(folder: string) {
	const name = stripOrder(folder);
	return name.charAt(0).toUpperCase() + name.slice(1).replaceAll("-", " ");
}

/** Splits `---\ntitle: X\ndescription: Y\n---` off the MDX; only flat `key: value` lines. */
function frontmatter(source: string, file: string) {
	const match = /^---\n([\s\S]*?)\n---\n?/.exec(source);
	if (!match) throw new Error(`${file}: no frontmatter`);
	const data: Record<string, string> = {};
	for (const line of match[1].split("\n")) {
		const kv = /^(\w+):\s*(.*)$/.exec(line);
		if (kv) data[kv[1]] = kv[2].replace(/^(["'])(.*)\1$/, "$2");
	}
	if (!data.title) throw new Error(`${file}: no title`);
	return { data, body: source.slice(match[0].length) };
}

function readPage(path: string, section?: string): Page {
	const file = relative(docsDir, path);
	const { data, body } = frontmatter(readFileSync(path, "utf8"), file);
	const slug = file
		.replace(/\.mdx?$/, "")
		.split("/")
		.map(stripOrder)
		.filter((s) => s !== "index");
	return {
		url: ["/docs", ...slug].join("/"),
		file,
		title: data.title,
		description: data.description ?? "",
		body,
		section,
	};
}

const sorted = (dir: string) =>
	readdirSync(dir)
		.filter((name) => !name.startsWith("."))
		.sort();

export function loadDocs(): Docs {
	const intro = readPage(join(docsDir, "index.mdx"));
	const sections: Section[] = [];
	for (const folder of sorted(docsDir)) {
		const dir = join(docsDir, folder);
		if (!statSync(dir).isDirectory()) continue;
		const index = sorted(dir).find((f) => /^index\.mdx?$/.test(f));
		const title = index
			? readPage(join(dir, index)).title
			: sectionTitle(folder);
		const pages = sorted(dir)
			.filter((f) => /\.mdx?$/.test(f))
			.map((f) => readPage(join(dir, f), title));
		sections.push({ title, pages });
	}
	const pages = [intro, ...sections.flatMap((s) => s.pages)];
	const urls = new Set<string>();
	for (const page of pages) {
		if (urls.has(page.url)) throw new Error(`two pages for ${page.url}`);
		urls.add(page.url);
	}
	return { pages, intro, sections };
}
