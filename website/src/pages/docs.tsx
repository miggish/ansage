import {
	ChevronDown,
	ChevronLeft,
	ChevronRight,
	Copy,
	FileText,
	Pencil,
	TextAlignStart,
} from "lucide-react";
import type { MDXContent } from "mdx/types";
import { Document, SiteHeader } from "@/components/layout";
import { mdxComponents } from "@/components/mdx";
import type { Docs, Page } from "@/content";
import { cn } from "@/lib/cn";
import { gitConfig, repoUrl } from "@/lib/site";
import type { TocItem } from "@/mdx";

const markdownUrl = (page: Page) => `${page.url}.md`;

function Sidebar({ docs, current }: { docs: Docs; current: Page }) {
	const item = (page: Page) => (
		<a
			key={page.url}
			href={page.url}
			aria-current={page.url === current.url ? "page" : undefined}
			className={cn(
				"block border-l px-3 py-1.5 text-sm transition-colors",
				page.url === current.url
					? "border-fg bg-surface-2 font-medium text-fg"
					: "border-transparent text-fg-muted hover:bg-surface-2/50 hover:text-fg",
			)}
		>
			{page.title}
		</a>
	);
	return (
		<nav aria-label="Docs" className="space-y-6">
			<div>{item(docs.intro)}</div>
			{docs.sections.map((section) => (
				<div key={section.title}>
					<p className="ds-label mb-1.5 px-3">{section.title}</p>
					{section.pages.map(item)}
				</div>
			))}
		</nav>
	);
}

function Toc({ toc }: { toc: TocItem[] }) {
	if (toc.length === 0) return null;
	return (
		<nav aria-label="On this page" className="text-sm">
			<p className="ds-label mb-3 flex items-center gap-2">
				<TextAlignStart className="size-3.5" /> On this page
			</p>
			<ul className="space-y-2 border-l">
				{toc.map((t) => (
					<li key={t.id}>
						<a
							href={`#${t.id}`}
							className={cn(
								"-ml-px block border-l border-transparent text-fg-muted transition-colors hover:border-fg hover:text-fg",
								t.depth === 2 ? "ps-3" : "ps-6",
							)}
						>
							{t.text}
						</a>
					</li>
				))}
			</ul>
		</nav>
	);
}

function PageActions({ page }: { page: Page }) {
	const button = "ds-button px-2.5 py-1.5";
	return (
		<div className="flex flex-wrap items-center gap-2">
			<button
				type="button"
				data-copy-url={markdownUrl(page)}
				data-variant="secondary"
				className={button}
			>
				<Copy className="size-3.5" /> Copy Markdown
			</button>
			<a href={markdownUrl(page)} data-variant="secondary" className={button}>
				<FileText className="size-3.5" /> View as Markdown
			</a>
			<a
				href={`${repoUrl}/blob/${gitConfig.branch}/docs/${page.file}`}
				data-variant="secondary"
				className={button}
			>
				<Pencil className="size-3.5" /> Edit on GitHub
			</a>
		</div>
	);
}

function PrevNext({ docs, page }: { docs: Docs; page: Page }) {
	const i = docs.pages.findIndex((p) => p.url === page.url);
	const prev = docs.pages[i - 1];
	const next = docs.pages[i + 1];
	const card =
		"ds-box group flex flex-col gap-1 p-4 text-sm transition-colors hover:bg-surface-2";
	return (
		<nav className="mt-16 grid gap-3 sm:grid-cols-2">
			{prev ? (
				<a href={prev.url} className={card}>
					<span className="ds-label flex items-center gap-1">
						<ChevronLeft className="size-3.5" /> Previous
					</span>
					<span className="font-medium">{prev.title}</span>
				</a>
			) : (
				<span />
			)}
			{next && (
				<a href={next.url} className={cn(card, "text-right")}>
					<span className="ds-label flex items-center justify-end gap-1">
						Next <ChevronRight className="size-3.5" />
					</span>
					<span className="font-medium">{next.title}</span>
				</a>
			)}
		</nav>
	);
}

export function DocsPage({
	docs,
	page,
	Content,
	toc,
	dev,
}: {
	docs: Docs;
	page: Page;
	Content: MDXContent;
	toc: TocItem[];
	dev?: boolean;
}) {
	return (
		<Document
			title={page.url === "/docs" ? "ansage docs" : `${page.title} · ansage`}
			description={page.description}
			markdownUrl={markdownUrl(page)}
			dev={dev}
		>
			<SiteHeader url={page.url} />
			<div className="ds-frame flex-row">
				<aside className="docs-rail hidden w-64 shrink-0 border-r px-4 py-8 md:block">
					<Sidebar docs={docs} current={page} />
				</aside>

				<main className="min-w-0 flex-1 px-4 py-8 md:px-12 md:py-12">
					{/* phones: the sidebar as a native dropdown */}
					<details className="smooth group mb-8 border md:hidden">
						<summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3 text-sm">
							<span>
								<span className="text-fg-muted">
									{page.section ?? "Docs"} /
								</span>{" "}
								{page.title}
							</span>
							<ChevronDown className="size-4 transition-transform group-open:rotate-180" />
						</summary>
						<div className="border-t p-3">
							<Sidebar docs={docs} current={page} />
						</div>
					</details>

					<article data-pagefind-body className="mx-auto max-w-3xl">
						<h1 className="text-3xl font-semibold tracking-tight md:text-4xl">
							{page.title}
						</h1>
						{page.description && (
							<p className="mt-3 text-lg text-fg-muted">{page.description}</p>
						)}
						<div data-pagefind-ignore className="dashed-border-b mt-5 pb-6">
							<PageActions page={page} />
						</div>
						<div className="prose mt-8">
							<Content components={mdxComponents} />
						</div>
					</article>
					<div className="mx-auto max-w-3xl">
						<PrevNext docs={docs} page={page} />
					</div>
				</main>

				<aside className="docs-rail hidden w-64 shrink-0 px-4 py-12 xl:block">
					<Toc toc={toc} />
				</aside>
			</div>
		</Document>
	);
}
