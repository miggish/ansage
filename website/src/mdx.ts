// Compiles a docs page's MDX into a component (rendered to HTML at build time, never in the
// browser): GFM tables, Shiki highlighting for both themes, ids and anchors on h2/h3, and the
// table of contents.
import { evaluate } from "@mdx-js/mdx";
import rehypeShiki from "@shikijs/rehype";
import GithubSlugger from "github-slugger";
import type { Element, ElementContent, Root } from "hast";
import { toString as hastToString } from "hast-util-to-string";
import type { MDXContent } from "mdx/types";
import * as runtime from "react/jsx-runtime";
import remarkGfm from "remark-gfm";
import { visit } from "unist-util-visit";

export interface TocItem {
	depth: 2 | 3;
	id: string;
	text: string;
}

/** ids from the heading text (like GitHub), a link on the heading, and the TOC entries */
function rehypeHeadings(toc: TocItem[]) {
	return () => (tree: Root) => {
		const slugger = new GithubSlugger();
		visit(tree, "element", (node: Element) => {
			if (node.tagName !== "h2" && node.tagName !== "h3") return;
			const text = hastToString(node);
			const id = slugger.slug(text);
			node.properties.id = id;
			toc.push({ depth: node.tagName === "h2" ? 2 : 3, id, text });
			node.children = [
				{
					type: "element",
					tagName: "a",
					properties: { href: `#${id}`, className: ["heading-anchor"] },
					children: node.children as ElementContent[],
				},
			];
		});
	};
}

/** ```toml title="/etc/ansage/ansage.toml" -> data-title on the <pre> */
function parseMetaString(meta: string) {
	const title = /title="([^"]*)"/.exec(meta)?.[1];
	return title ? { "data-title": title } : {};
}

export async function compilePage(body: string) {
	const toc: TocItem[] = [];
	const { default: Content } = (await evaluate(body, {
		...runtime,
		remarkPlugins: [remarkGfm],
		rehypePlugins: [
			[
				rehypeShiki,
				{
					themes: { light: "github-light", dark: "github-dark" },
					defaultColor: false,
					defaultLanguage: "txt",
					fallbackLanguage: "txt",
					parseMetaString,
				},
			],
			rehypeHeadings(toc),
		],
	})) as { default: MDXContent };
	return { Content, toc };
}
