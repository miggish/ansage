// The MDX components of the docs, rendered to HTML at build time. Every one of them needs a
// Markdown form in src/markdown.ts too (checked by the build).
import { ArrowRight, Check, Copy, Info, TriangleAlert } from "lucide-react";
import type { MDXComponents } from "mdx/types";
import { Children, type ComponentProps, type ReactNode, useId } from "react";
import { ConfigReference } from "@/components/config-reference";
import { cn } from "@/lib/cn";

const shellLanguages = ["sh", "bash", "shell", "console"];

/** A code block from Shiki, with its title (```toml title="…") and a copy button: always
 * visible on shell commands, on hover (or a touch screen) elsewhere. */
function Pre({
	"data-title": title,
	"data-language": language,
	className,
	...props
}: ComponentProps<"pre"> & {
	"data-title"?: string;
	"data-language"?: string;
}) {
	const shell = shellLanguages.includes(language ?? "");
	return (
		<figure className="not-prose my-6 border bg-surface">
			{title && (
				<figcaption className="ds-label border-b px-4 py-2 normal-case">
					{title}
				</figcaption>
			)}
			<div className="group relative">
				<pre
					{...props}
					className={cn(
						className,
						"overflow-x-auto px-4 py-3.5 font-mono text-sm leading-relaxed",
					)}
				/>
				<button
					type="button"
					data-copy-code
					aria-label={shell ? "Copy the commands" : "Copy the code"}
					className={cn(
						"code-copy absolute top-2.5 right-2.5 border bg-bg p-1.5 text-fg-muted transition-opacity hover:text-fg focus-visible:opacity-100",
						!shell &&
							"opacity-0 group-hover:opacity-100 [@media(hover:none)]:opacity-100",
					)}
				>
					<Copy className="copy-icon size-3.5" />
					<Check className="copied-icon size-3.5 text-ok" />
				</button>
			</div>
		</figure>
	);
}

const calloutStyle = {
	info: { icon: Info, title: "Note", tone: "info", color: "text-info" },
	warn: {
		icon: TriangleAlert,
		title: "Warning",
		tone: "warn",
		color: "text-warn",
	},
};

function Callout({
	type = "info",
	title,
	children,
}: {
	type?: keyof typeof calloutStyle;
	title?: string;
	children: ReactNode;
}) {
	const style = calloutStyle[type] ?? calloutStyle.info;
	const Icon = style.icon;
	return (
		<aside
			data-tone={style.tone}
			className="ds-callout not-prose my-6 flex gap-3 px-4 py-3.5 text-sm sm:px-4 sm:py-3.5"
		>
			<Icon className={cn("mt-0.5 size-4 shrink-0", style.color)} />
			<div className="min-w-0">
				<p className="font-semibold">{title ?? style.title}</p>
				<div className="callout-body prose prose-sm mt-1">{children}</div>
			</div>
		</aside>
	);
}

/** Tabs without JavaScript: one radio per tab, CSS shows the checked one's panel. */
function Tabs({ items, children }: { items: string[]; children: ReactNode }) {
	const id = useId();
	return (
		<div className="tabs doc-tabs my-6 border">
			{items.map((item, i) => (
				<input
					key={item}
					type="radio"
					name={id}
					id={`${id}-${i}`}
					defaultChecked={i === 0}
				/>
			))}
			<div className="tablist not-prose flex gap-4 border-b bg-surface px-4 text-sm">
				{items.map((item, i) => (
					<label key={item} htmlFor={`${id}-${i}`} className="py-2.5">
						{item}
					</label>
				))}
			</div>
			<div className="panels px-4">{children}</div>
		</div>
	);
}

function Tab({ children }: { value: string; children: ReactNode }) {
	return <div>{children}</div>;
}

function Steps({ children }: { children: ReactNode }) {
	return <div className="steps my-6">{children}</div>;
}

function Step({ children }: { children: ReactNode }) {
	return <div className="step">{children}</div>;
}

function Cards({ children }: { children: ReactNode }) {
	return (
		<div className="not-prose my-6 grid gap-3 sm:grid-cols-2">
			{Children.toArray(children)}
		</div>
	);
}

function Card({
	title,
	href,
	children,
}: {
	title: string;
	href: string;
	children: ReactNode;
}) {
	return (
		<a
			href={href}
			className="ds-box group block p-4 transition-colors hover:bg-surface-2"
		>
			<p className="flex items-center gap-1.5 font-medium">
				{title}
				<ArrowRight className="size-3.5 text-fg-muted transition-transform group-hover:translate-x-0.5" />
			</p>
			<div className="mt-1 text-sm text-fg-muted">{children}</div>
		</a>
	);
}

/** Wide tables scroll on their own instead of widening the page. */
function Table(props: ComponentProps<"table">) {
	return (
		<div className="overflow-x-auto">
			<table {...props} />
		</div>
	);
}

export const mdxComponents: MDXComponents = {
	pre: Pre,
	table: Table,
	Callout,
	Tabs,
	Tab,
	Steps,
	Step,
	Cards,
	Card,
	ConfigReference,
};
