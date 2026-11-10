// The Markdown form of a docs page, for agents (/docs/x.md, llms-full.txt).
// MDX components become plain Markdown, one renderer per component; a component without a
// renderer fails the build, so no JSX reaches an agent.
import type { Nodes, Root, RootContent } from "mdast";
import type { MdxJsxAttribute, MdxJsxFlowElement } from "mdast-util-mdx-jsx";
import remarkGfm from "remark-gfm";
import remarkMdx from "remark-mdx";
import remarkParse from "remark-parse";
import remarkStringify from "remark-stringify";
import { unified } from "unified";
import type { Page } from "./content";
import { configMarkdown } from "./lib/config-markdown.mjs";

type Attributes = Record<string, string | undefined>;
type Renderer = (attributes: Attributes, children: string) => string;

const quote = (text: string) =>
	text
		.trim()
		.split("\n")
		.map((line) => (line ? `> ${line}` : ">"))
		.join("\n");

const calloutLabel: Record<string, string> = {
	info: "Note",
	warn: "Warning",
	error: "Danger",
	success: "Tip",
};

const renderers: Record<string, Renderer> = {
	Callout: (a, children) =>
		quote(
			`**${a.title ?? calloutLabel[a.type ?? "info"] ?? "Note"}:** ${children.trim()}`,
		),
	Tabs: (_, children) => children.trim(),
	Tab: (a, children) => `**${a.value}:**\n\n${children.trim()}`,
	Steps: (_, children) => children.trim(),
	Step: (_, children) => children.trim(),
	Cards: (_, children) => children.trim(),
	Card: (a, children) => `- [${a.title}](${a.href}): ${children.trim()}`,
	ConfigReference: () => configMarkdown(),
};

/** The MDX components the docs may use: the HTML side must render the same set. */
export const markdownComponents = Object.keys(renderers);

const processor = unified()
	.use(remarkParse)
	.use(remarkMdx)
	.use(remarkGfm)
	.use(remarkStringify, { bullet: "-", fences: true, rule: "-" });

const stringify = (children: RootContent[]) =>
	processor.stringify({ type: "root", children } as Root);

function attributes(node: MdxJsxFlowElement): Attributes {
	const out: Attributes = {};
	for (const attr of node.attributes) {
		const { name, value } = attr as MdxJsxAttribute;
		if (typeof value === "string") out[name] = value;
	}
	return out;
}

/** Replaces every JSX element (innermost first) with its Markdown, as a raw node. */
function lower(node: Nodes, file: string): void {
	if (!("children" in node)) return;
	node.children = node.children.flatMap((child): RootContent[] => {
		lower(child, file);
		if (child.type === "mdxjsEsm") return [];
		if (
			child.type === "mdxJsxFlowElement" ||
			child.type === "mdxJsxTextElement"
		) {
			const name = child.name ?? "";
			const render = renderers[name];
			if (!render) {
				throw new Error(
					`${file}: <${name}> has no Markdown form; add it to src/markdown.ts`,
				);
			}
			const md = render(
				attributes(child as MdxJsxFlowElement),
				stringify(child.children as RootContent[]),
			);
			return [{ type: "html", value: md }];
		}
		return [child];
	}) as typeof node.children;
}

/** Keep agents on Markdown: links to /docs/foo become /docs/foo.md. */
export function mdLinks(md: string): string {
	return md.replace(
		/\]\((\/docs(?:\/[^)#\s]*)?)(#[^)]*)?\)/g,
		(_, path: string, hash = "") => `](${path.replace(/\/$/, "")}.md${hash})`,
	);
}

/** The page as Markdown: `# title`, `> description`, the body. */
export function pageMarkdown(page: Page): string {
	const tree = processor.parse(page.body) as Root;
	lower(tree, page.file);
	const body = processor
		.stringify(tree)
		.replace(/\n{3,}/g, "\n\n")
		.trim();
	const head = page.description
		? `# ${page.title}\n\n> ${page.description}`
		: `# ${page.title}`;
	return mdLinks(`${head}\n\n${body}\n`);
}
