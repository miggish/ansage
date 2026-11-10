import { cn } from "@/lib/cn";

/** A terminal line: a command, plain output, a line that matters, or a comment. */
type Line = [kind: "cmd" | "out" | "hi" | "dim", text: string];

interface Tab {
	id: string;
	title: string;
	subtitle: string;
	lines: Line[];
	note: string;
	link: { text: string; href: string };
}

// Real output of ansage 0.2.0 (two local instances peering over loopback), and the
// result of the end-to-end tests G1 and G8 (test/e2e/scenarios/graceful.sh).
const tabs: Tab[] = [
	{
		id: "show",
		title: "Your prefixes, at a glance",
		subtitle: "ansage show · one eBGP neighbor",
		lines: [
			["cmd", "ansage show summary"],
			["out", "ansage 0.2.0, AS 64500, router ID 203.0.113.1, up 19.0s"],
			["out", "RIB: 1 IPv4 and 1 IPv6 prefixes, 1 attribute sets"],
			["hi", "Announcing: 192.0.2.0/24 2001:db8:1::/48"],
			["out", ""],
			["dim", "ID  NEIGHBOR         AS     STATE        FOR    SENT v4/v6"],
			["hi", "1   127.0.0.2:11790  64501  Established  12.8s  1/1"],
		],
		note: "Output of ansage 0.2.0, columns shortened. Every client command also takes --json.",
		link: {
			text: "first session",
			href: "/docs/getting-started/first-session",
		},
	},
	{
		id: "drain",
		title: "Drain before maintenance",
		subtitle: "RFC 8326 · sessions stay up, traffic moves",
		lines: [
			["cmd", "ansage drain"],
			[
				"hi",
				"Drained: our routes go out with GRACEFUL_SHUTDOWN 65535:0 until `ansage undrain`",
			],
			["cmd", "ansage show summary"],
			["out", "ansage 0.2.0, AS 64500, router ID 203.0.113.1, up 20.0s"],
			["out", "Announcing: 192.0.2.0/24 2001:db8:1::/48"],
			[
				"hi",
				"Drained for 1.0s: our routes carry GRACEFUL_SHUTDOWN (ansage undrain ends it)",
			],
			["cmd", "ansage undrain"],
			["out", "Drain ended: our routes go out as usual"],
		],
		note: "Routers move traffic to the other sites while this one still answers. drain_time does the same on every stop.",
		link: { text: "drain guide", href: "/docs/guides/drain" },
	},
	{
		id: "upgrade",
		title: "Upgrade without dropping routes",
		subtitle: "graceful restart · RFC 4724 + RFC 8538",
		lines: [
			["cmd", "ansage upgrade --binary /usr/local/bin/ansage"],
			[
				"out",
				"  127.0.0.2:11790   keeps our routes for 30 s (Cease without Hard Reset)",
			],
			["out", "New binary: ansage 0.2.0, config OK"],
			["out", "Restarting; waiting up to 30 s for 1 neighbors"],
			["hi", "ansage is back after 0.3 s"],
			["hi", "  127.0.0.2:11790   back after 0.3 s"],
			["hi", "Upgrade done"],
		],
		note: "In the end-to-end tests, users behind FRR and BIRD fetched the anycast service every 0.1 s through ansage upgrade: no request failed.",
		link: { text: "reproduce", href: "/docs/development/e2e" },
	},
	{
		id: "config",
		title: "One small config file",
		subtitle: "/etc/ansage/ansage.toml",
		lines: [
			["out", "asn = 64500"],
			["out", 'router_id = "203.0.113.1"'],
			["hi", 'announce = ["192.0.2.0/24", "2001:db8:1::/48"]'],
			["out", ""],
			["out", "[[neighbor]]"],
			["out", 'address = "10.0.0.1"'],
			["out", "asn = 64501"],
		],
		note: "ansage reload applies only what changed; unchanged neighbors keep their sessions.",
		link: { text: "config reference", href: "/docs/reference/config" },
	},
];

/** Tabs without JavaScript: a radio per tab, CSS (styles.css, .tabs) shows the checked one. */
export function TerminalTabs() {
	return (
		<div className="tabs terminal-tabs ds-box bg-terminal text-terminal-foreground">
			{tabs.map((t, i) => (
				<input
					key={t.id}
					type="radio"
					name="terminal"
					id={`terminal-${t.id}`}
					defaultChecked={i === 0}
				/>
			))}
			<div className="tablist grid grid-cols-4 border-b border-terminal-border">
				{tabs.map((t) => (
					<label
						key={t.id}
						htmlFor={`terminal-${t.id}`}
						className="border-r border-terminal-border py-3 text-center font-mono text-sm text-terminal-muted transition-colors last:border-r-0 hover:text-terminal-foreground"
					>
						{t.id}
					</label>
				))}
			</div>

			<div className="panels">
				{tabs.map((tab) => (
					<div key={tab.id} className="p-5 md:p-6">
						<p className="font-semibold">{tab.title}</p>
						<p className="mt-0.5 text-sm text-terminal-muted">{tab.subtitle}</p>

						<pre className="mt-5 min-h-54 overflow-x-auto font-mono text-xs leading-relaxed">
							{tab.lines.map(([kind, text], i) => (
								<div
									// biome-ignore lint/suspicious/noArrayIndexKey: static lines, never reordered
									key={i}
									className={cn(
										kind === "out" && "text-terminal-foreground/80",
										kind === "dim" && "text-terminal-muted",
										kind === "hi" && "text-terminal-accent",
										kind === "cmd" &&
											"mt-2 text-terminal-foreground first:mt-0",
									)}
								>
									{kind === "cmd" && (
										<span className="text-terminal-accent">$ </span>
									)}
									{text || " "}
								</div>
							))}
						</pre>

						<div className="mt-5 flex items-start justify-between gap-6 border-t border-terminal-border pt-4 text-xs text-terminal-muted">
							<p className="max-w-md leading-relaxed">{tab.note}</p>
							<a
								href={tab.link.href}
								className="shrink-0 underline underline-offset-4 hover:text-terminal-foreground"
							>
								{tab.link.text}
							</a>
						</div>
					</div>
				))}
			</div>
		</div>
	);
}
