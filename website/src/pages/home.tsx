import {
	Activity,
	ArrowRight,
	ArrowUpRight,
	Cpu,
	HardDriveDownload,
	Shield,
	SlidersHorizontal,
	Waves,
} from "lucide-react";
import { Bracketed, Eyebrow, Section } from "@/components/frame";
import { AnycastDiagram } from "@/components/home/anycast-diagram";
import { InstallCommand } from "@/components/home/install-command";
import { TerminalTabs } from "@/components/home/terminal-tabs";
import { Document, SiteHeader } from "@/components/layout";
import { release, repoUrl } from "@/lib/site";

const install = `curl -fsSL ${repoUrl}/releases/latest/download/install.sh | sudo sh`;

const testedWith = [
	"FRR",
	"BIRD",
	"Linux FIB",
	"Prometheus",
	"systemd 252 + 255",
];

const features = [
	{
		icon: Waves,
		title: "Drain before maintenance",
		text: "RFC 8326: routers move traffic to the other sites while this one still answers. Sessions stay up.",
		href: "/docs/guides/drain",
	},
	{
		icon: HardDriveDownload,
		title: "Upgrade in place",
		text: "ansage upgrade restarts with Graceful Restart and exits 0 only once every neighbor has the full table again.",
		href: "/docs/guides/upgrades",
	},
	{
		icon: SlidersHorizontal,
		title: "Change at runtime",
		text: "ansage announce and withdraw for health checks; ansage reload applies only what changed.",
		href: "/docs/guides/health-checks",
	},
	{
		icon: Cpu,
		title: "Kernel routes",
		text: "With [kernel], the best learned routes go into the Linux routing table through nexthop objects.",
		href: "/docs/guides/kernel-routes",
	},
	{
		icon: Activity,
		title: "Observable",
		text: "ansage show, Prometheus metrics, a read-only JSON API and live events over SSE.",
		href: "/docs/guides/metrics-api",
	},
	{
		icon: Shield,
		title: "Locked down",
		text: "TCP-MD5 and GTSM per neighbor, a hardened systemd unit, its own user and group.",
		href: "/docs/guides/security",
	},
];

const agents = [
	["/llms.txt", "Index of every page with its Markdown URL."],
	["/docs/….md", "Any page as clean Markdown, or send Accept: text/markdown."],
	["/llms-full.txt", "All docs in one file."],
];

export function HomePage({ dev }: { dev?: boolean }) {
	return (
		<Document
			title="ansage: BGP router for Linux"
			description="ansage is a BGP router for Linux, written in Rust and growing into a replacement for BIRD and FRR. Today it announces anycast services and your IPv4 and IPv6 ranges, passes routes on to customers, drains before maintenance and upgrades without dropping routes."
			dev={dev}
		>
			<SiteHeader url="/" />
			<div className="ds-frame">
				<main className="flex-1">
					<Section inner="grid gap-12 py-16 md:py-24 lg:grid-cols-2 lg:items-center lg:gap-14">
						<div>
							<a
								href={release.url}
								className="group mb-7 inline-flex items-center gap-2.5 font-mono text-xs tracking-widest uppercase"
							>
								<span data-tone="ok" className="ds-tag">
									New
								</span>
								<span className="text-fg-muted group-hover:text-fg">
									ansage {release.version} released
								</span>
								<ArrowRight className="size-3 text-fg-muted transition-transform group-hover:translate-x-0.5" />
							</a>

							<h1 className="text-4xl leading-none font-bold tracking-tighter text-balance sm:text-5xl xl:text-6xl">
								Your prefixes, <span className="text-ok">announced</span>.{" "}
								<span className="text-fg-muted">
									Drained and upgraded without a gap.
								</span>
							</h1>

							<p className="mt-7 max-w-xl text-lg leading-relaxed text-fg-muted">
								ansage is a BGP router for Linux, growing into a replacement for
								BIRD and FRR. Today it announces anycast services and your IPv4
								and IPv6 ranges to your routers,{" "}
								<a
									href="/docs/guides/drain"
									className="text-fg underline decoration-fg-subtle underline-offset-4 hover:decoration-fg"
								>
									drains
								</a>{" "}
								a site before maintenance and{" "}
								<a
									href="/docs/guides/upgrades"
									className="text-fg underline decoration-fg-subtle underline-offset-4 hover:decoration-fg"
								>
									upgrades
								</a>{" "}
								without dropping routes.
							</p>

							<div className="mt-10 max-w-xl">
								<p className="ds-label mb-3 text-xs">
									Install ansage {release.version}
								</p>
								<InstallCommand command={install} />
								<div className="mt-3 flex items-center justify-between gap-4 text-xs text-fg-muted">
									<span className="font-mono">
										Linux · x86_64, aarch64 · systemd
									</span>
									<a
										href={`${repoUrl}/blob/main/dist/install.sh`}
										className="inline-flex items-center gap-1 hover:text-fg"
									>
										View install script <ArrowUpRight className="size-3" />
									</a>
								</div>
								<a
									href="/docs/getting-started/first-session"
									className="group mt-7 inline-flex items-center gap-2 font-medium underline decoration-fg-subtle underline-offset-4 hover:decoration-fg"
								>
									Then announce your first prefix
									<ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
								</a>
							</div>
						</div>

						<TerminalTabs />
					</Section>

					<Section inner="flex flex-col gap-5 py-8 md:flex-row md:items-center md:gap-12">
						<Eyebrow className="shrink-0">Tested against</Eyebrow>
						<ul className="flex flex-wrap items-center gap-x-10 gap-y-3">
							{testedWith.map((name) => (
								<li
									key={name}
									className="text-xl font-semibold tracking-tight text-fg-muted"
								>
									{name}
								</li>
							))}
						</ul>
					</Section>

					<Section inner="py-20 md:py-28">
						<div className="mx-auto mb-12 max-w-2xl text-center">
							<h2 className="text-4xl font-semibold tracking-tight md:text-5xl">
								One prefix, every site.
							</h2>
							<p className="mt-5 text-lg text-fg-muted">
								Each site runs ansage and announces the same prefix. Routers
								send users to the nearest one; drain a site and its traffic
								moves before you touch it.
							</p>
						</div>
						<AnycastDiagram
							left={
								<Bracketed>
									<p className="font-semibold">Drain, RFC 8326</p>
									<p className="mt-1 text-sm text-fg-muted">
										GRACEFUL_SHUTDOWN 65535:0, LOCAL_PREF 0 on iBGP, extra AS
										prepends on eBGP.
									</p>
								</Bracketed>
							}
							right={
								<Bracketed>
									<p className="font-semibold">0 failed requests</p>
									<p className="mt-1 text-sm text-fg-muted">
										Users fetched the service every 0.1 s through ansage
										upgrade, in the end-to-end tests.
									</p>
								</Bracketed>
							}
						/>
						<p className="mt-10 text-center font-mono text-xs text-fg-muted">
							The network of ansage's{" "}
							<a
								href="/docs/development/e2e"
								className="underline underline-offset-4 hover:text-fg"
							>
								end-to-end tests
							</a>
							, simplified.
						</p>
					</Section>

					<Section bleed>
						{/* mx-px: the cells are opaque; keep them off the frame's dashed guide lines */}
						<div className="mx-px grid gap-px bg-line sm:grid-cols-2 lg:grid-cols-3">
							{features.map(({ icon: Icon, title, text, href }) => (
								<a
									key={title}
									href={href}
									className="group bg-bg p-8 transition-colors hover:bg-surface-2/50 md:p-10"
								>
									<Icon
										className="size-6 text-fg-muted transition-colors group-hover:text-ok"
										strokeWidth={1.5}
									/>
									<h3 className="mt-5 font-semibold">{title}</h3>
									<p className="mt-2 text-sm leading-relaxed text-fg-muted">
										{text}
									</p>
								</a>
							))}
						</div>
					</Section>

					<Section inner="grid gap-10 py-20 md:grid-cols-5 md:py-24">
						<div className="md:col-span-2">
							<Eyebrow>For agents</Eyebrow>
							<h2 className="mt-4 text-3xl font-semibold tracking-tight">
								The same docs, as Markdown.
							</h2>
							<p className="mt-4 text-fg-muted">
								Point your coding agent at ansage: every page has a Markdown
								twin.
							</p>
						</div>
						<dl className="ds-box grid gap-px bg-line md:col-span-3">
							{agents.map(([path, text]) => (
								<div key={path} className="bg-surface p-5">
									<dt className="font-mono text-sm">{path}</dt>
									<dd className="mt-1.5 text-sm text-fg-muted">{text}</dd>
								</div>
							))}
						</dl>
					</Section>

					<Section
						rule={false}
						inner="flex flex-col items-start justify-between gap-8 py-16 md:flex-row md:items-center"
					>
						<h2 className="text-3xl font-semibold tracking-tight md:text-4xl">
							Announce your first prefix.
						</h2>
						<div className="flex gap-3">
							<a
								href="/docs/getting-started/install"
								className="ds-button px-5 py-2.5"
							>
								Get started
							</a>
							<a
								href="/docs"
								data-variant="secondary"
								className="ds-button px-5 py-2.5"
							>
								Read the docs
							</a>
						</div>
					</Section>
				</main>

				<footer className="ds-footer font-mono">
					<div aria-hidden="true" className="ds-rule" />
					<div className="ds-footer__inner">
						<span>ansage · MIT license</span>
						<nav className="flex gap-6">
							<a href="/docs" className="hover:text-fg">
								Docs
							</a>
							<a href={repoUrl} className="hover:text-fg">
								GitHub
							</a>
							<a href={`${repoUrl}/releases`} className="hover:text-fg">
								Releases
							</a>
						</nav>
					</div>
				</footer>
			</div>
		</Document>
	);
}
