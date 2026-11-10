import { ArrowRight, Menu, Moon, Search, Sun } from "lucide-react";
import type { ReactNode } from "react";
import { Logo } from "@/components/logo";
import { cn } from "@/lib/cn";
import { appName, release, repoUrl } from "@/lib/site";

// Applies a theme chosen with the toggle before the first paint (no flash). Without a stored
// choice the CSS follows the system on its own.
const themeScript = `try{var t=localStorage.getItem("theme");if(t==="dark"||t==="light")document.documentElement.dataset.theme=t}catch(e){}`;

// In `bun run dev` only: reload when the build changed.
const reloadScript = `new EventSource("/__reload").onmessage=function(){location.reload()}`;

export function Document({
	title,
	description,
	markdownUrl,
	dev,
	children,
}: {
	title: string;
	description: string;
	markdownUrl?: string;
	dev?: boolean;
	children: ReactNode;
}) {
	return (
		<html lang="en">
			<head>
				<meta charSet="utf-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1" />
				<title>{title}</title>
				<meta name="description" content={description} />
				{/* biome-ignore lint/security/noDangerouslySetInnerHtml: a fixed inline script */}
				<script dangerouslySetInnerHTML={{ __html: themeScript }} />
				<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
				<link
					rel="preload"
					href="/assets/fonts/geist-latin-wght-normal.woff2"
					as="font"
					type="font/woff2"
					crossOrigin=""
				/>
				<link rel="stylesheet" href="/assets/style.css" />
				{markdownUrl && (
					// lets agents that land on the HTML page find its Markdown form
					<link rel="alternate" type="text/markdown" href={markdownUrl} />
				)}
				<script src="/assets/site.js" defer />
				{dev && (
					// biome-ignore lint/security/noDangerouslySetInnerHtml: a fixed inline script
					<script dangerouslySetInnerHTML={{ __html: reloadScript }} />
				)}
			</head>
			<body>
				<div className="ds-page">
					<Banner />
					{children}
				</div>
				<SearchDialog />
			</body>
		</html>
	);
}

function Banner() {
	return (
		<div className="ds-dashed-border-b flex h-10 items-center justify-center px-4 text-sm">
			<a
				href={release.url}
				className="group inline-flex items-center gap-2 text-fg-muted transition-colors hover:text-fg"
			>
				<span data-tone="ok" className="ds-tag">
					New
				</span>
				<span className="hidden sm:inline">
					ansage {release.version} is out: {release.highlights}
				</span>
				<span className="sm:hidden">ansage {release.version} is out</span>
				<ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
			</a>
		</div>
	);
}

const links = [
	{ text: "Docs", href: "/docs" },
	{ text: "Guides", href: "/docs/guides/anycast", section: "/docs/guides" },
	{
		text: "Reference",
		href: "/docs/reference/config",
		section: "/docs/reference",
	},
];

/** The link of the current page: Guides and Reference by section, Docs for the rest of /docs. */
function activeLink(url: string) {
	const section = links.find((l) => l.section && url.startsWith(l.section));
	if (section) return section.text;
	return url.startsWith("/docs") ? "Docs" : undefined;
}

function GitHubIcon({ className }: { className?: string }) {
	return (
		<svg
			viewBox="0 0 24 24"
			fill="currentColor"
			aria-hidden="true"
			className={className}
		>
			<path d="M12 .3a12 12 0 0 0-3.8 23.38c.6.12.83-.26.83-.57L9 21.07c-3.34.72-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.08-.74.09-.73.09-.73 1.2.09 1.83 1.24 1.83 1.24 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.31.76-1.61-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.14-.3-.54-1.52.1-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.28-1.55 3.29-1.23 3.29-1.23.64 1.66.24 2.88.12 3.18a4.65 4.65 0 0 1 1.23 3.22c0 4.61-2.8 5.63-5.48 5.92.42.36.81 1.1.81 2.22l-.01 3.29c0 .32.21.7.82.58A12 12 0 0 0 12 .3" />
		</svg>
	);
}

/** Switches light/dark; the icon shows the theme you get by clicking. Needs site.js. */
function ThemeToggle({ className }: { className?: string }) {
	return (
		<button
			type="button"
			data-theme-toggle
			aria-label="Switch between light and dark"
			className={cn(
				"p-2 text-fg-muted transition-colors hover:text-fg",
				className,
			)}
		>
			<Sun className="hidden size-5 dark:block" />
			<Moon className="size-5 dark:hidden" />
		</button>
	);
}

/** The header of every page: logo, links, search, install, GitHub, theme. */
export function SiteHeader({ url }: { url: string }) {
	const active = activeLink(url);
	const menuLink = "px-3 py-2 transition-colors hover:bg-surface-2";
	return (
		<header className="ds-header">
			<div className="ds-header__inner justify-start gap-2">
				<a href="/" className="ds-brand items-center gap-2.5">
					<Logo className="size-6" />
					<span className="ds-brand__name">{appName}</span>
				</a>

				<nav className="ds-nav ms-6 hidden md:flex">
					{links.map((l) => (
						<a
							key={l.text}
							href={l.href}
							aria-current={l.text === active ? "page" : undefined}
							className="ds-nav__link"
						>
							{l.text}
						</a>
					))}
					<a href="/docs/getting-started/install" className="ds-button ms-3">
						Install
					</a>
				</nav>

				<div className="ms-auto flex items-center gap-1">
					<button
						type="button"
						data-search-open
						className="hidden w-60 items-center gap-2 border bg-surface py-1.5 ps-3 pe-1.5 text-sm text-fg-subtle transition-colors hover:border-fg-subtle hover:text-fg-muted md:flex"
					>
						<Search className="size-4" />
						Search
						<kbd className="ms-auto border bg-bg px-1.5 font-mono text-xs">
							/
						</kbd>
					</button>
					<a
						href={repoUrl}
						aria-label="ansage on GitHub"
						className="hidden p-2 text-fg-muted transition-colors hover:text-fg md:block"
					>
						<GitHubIcon className="size-5" />
					</a>
					<ThemeToggle className="hidden md:block" />

					<button
						type="button"
						data-search-open
						aria-label="Search"
						className="p-2 text-fg-muted md:hidden"
					>
						<Search className="size-5" />
					</button>
					{/* a native dropdown: opens without JavaScript */}
					<details className="group relative md:hidden">
						<summary
							aria-label="Menu"
							className="cursor-pointer list-none p-2 text-fg-muted group-open:text-fg"
						>
							<Menu className="size-5" />
						</summary>
						<nav className="ds-popover absolute end-0 top-full mt-2 flex w-56 flex-col p-2 text-sm">
							{links.map((l) => (
								<a
									key={l.text}
									href={l.href}
									className={cn(
										menuLink,
										l.text === active ? "font-medium text-fg" : "text-fg-muted",
									)}
								>
									{l.text}
								</a>
							))}
							<a
								href="/docs/getting-started/install"
								className={cn(menuLink, "text-fg-muted")}
							>
								Install
							</a>
							<a href={repoUrl} className={cn(menuLink, "text-fg-muted")}>
								GitHub
							</a>
							<div className="mt-1 flex items-center justify-between border-t ps-3 pt-1">
								<span className="ds-label">Theme</span>
								<ThemeToggle />
							</div>
						</nav>
					</details>
				</div>
			</div>
		</header>
	);
}

/** Pagefind's search UI, loaded by site.js the first time the dialog opens. */
function SearchDialog() {
	return (
		<dialog
			id="search"
			aria-label="Search the docs"
			className="m-auto mt-24 w-full max-w-2xl border bg-surface p-4 text-fg shadow-2xl"
		>
			<div id="search-ui" />
			<p className="ds-label mt-3 text-right">Esc to close</p>
		</dialog>
	);
}
