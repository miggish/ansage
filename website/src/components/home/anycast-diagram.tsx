import { Router, User } from "lucide-react";
import type { ReactNode } from "react";
import { Logo } from "@/components/logo";
import { cn } from "@/lib/cn";

// The network of the end-to-end tests (test/e2e): ansage on three sites (srv-a, srv-b, srv-c)
// announcing the same prefix to two routers (FRR, BIRD), and two users behind them.
// Coordinates in the 800 x 450 (16:9) viewBox.
const nodes = {
	user1: { x: 90, y: 70, label: "users", kind: "user" },
	user2: { x: 710, y: 70, label: "users", kind: "user" },
	r1: { x: 250, y: 205, label: "router · FRR", kind: "router" },
	r2: { x: 550, y: 205, label: "router · BIRD", kind: "router" },
	a: { x: 120, y: 370, label: "site A", kind: "site" },
	c: { x: 400, y: 370, label: "site C", kind: "site" },
	b: { x: 680, y: 370, label: "site B", kind: "site" },
} as const;

type Id = keyof typeof nodes;

const links: [Id, Id][] = [
	["user1", "r1"],
	["user2", "r2"],
	["r1", "r2"],
	["r1", "a"],
	["r1", "c"],
	["r2", "c"],
	["r2", "b"],
];

const modes = {
	normal: {
		label: "All sites up",
		flows: [
			["user1", "r1", "a"],
			["user2", "r2", "b"],
		] as Id[][],
		caption:
			"ansage on every site announces 192.0.2.0/24. Each router sends its users to the nearest site.",
	},
	drain: {
		label: "Drain site A",
		flows: [
			["user1", "r1", "c"],
			["user2", "r2", "b"],
		] as Id[][],
		caption:
			"ansage drain on site A: its routes go out with GRACEFUL_SHUTDOWN, the FRR router moves to site C. Site A keeps answering while the traffic moves.",
	},
};

type Mode = keyof typeof modes;
const modeKeys = Object.keys(modes) as Mode[];

function path(ids: Id[]) {
	return ids
		.map((id, i) => `${i === 0 ? "M" : "L"}${nodes[id].x} ${nodes[id].y}`)
		.join(" ");
}

function Node({ id, drained = false }: { id: Id; drained?: boolean }) {
	const node = nodes[id];
	const site = node.kind === "site";
	const Icon = node.kind === "user" ? User : Router;
	return (
		<div
			className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-1.5"
			style={{
				left: `${(node.x / 800) * 100}%`,
				top: `${(node.y / 450) * 100}%`,
			}}
		>
			<div
				className={cn(
					"flex items-center justify-center border bg-bg",
					site
						? "size-11 border-ok/60 bg-ok/10 md:size-14"
						: "size-9 text-fg-muted md:size-11",
					drained && "border-dashed border-line bg-bg",
				)}
			>
				{site ? (
					<Logo
						className={cn(
							"size-6 md:size-8",
							drained && "opacity-40 grayscale",
						)}
					/>
				) : (
					<Icon className="size-4 md:size-5" strokeWidth={1.5} />
				)}
			</div>
			<span
				className={cn(
					"bg-bg px-1 font-mono text-xs whitespace-nowrap",
					site && !drained ? "text-fg" : "text-fg-muted",
				)}
			>
				{/* phones: the logo says ansage, the label just the site */}
				{site && <span className="hidden sm:inline">ansage · </span>}
				{node.label}
				{drained && " · drained"}
			</span>
		</div>
	);
}

/**
 * Two states without JavaScript: a radio per mode, CSS (styles.css, .diagram) shows the
 * elements of the checked one (.when-normal / .when-drain).
 */
export function AnycastDiagram({
	left,
	right,
}: {
	left: ReactNode;
	right: ReactNode;
}) {
	return (
		<div className="diagram">
			{modeKeys.map((m, i) => (
				<input
					key={m}
					type="radio"
					name="diagram"
					id={`diagram-${m}`}
					defaultChecked={i === 0}
				/>
			))}
			<div className="mb-8 flex justify-center">
				{/* styled like a .ds-segmented (styles.css, .diagram .modes) */}
				<div className="modes ds-segmented">
					{modeKeys.map((m) => (
						<label key={m} htmlFor={`diagram-${m}`} className="py-1">
							{modes[m].label}
						</label>
					))}
				</div>
			</div>

			<div className="grid items-center gap-8 lg:grid-cols-5">
				<div className="order-2 lg:order-1">{left}</div>

				<figure className="order-1 lg:order-2 lg:col-span-3">
					<div className="relative aspect-video w-full">
						<svg
							viewBox="0 0 800 450"
							className="absolute inset-0 size-full"
							aria-hidden="true"
						>
							{links.map(([from, to]) => (
								<line
									key={`${from}-${to}`}
									x1={nodes[from].x}
									y1={nodes[from].y}
									x2={nodes[to].x}
									y2={nodes[to].y}
									className="stroke-line"
									strokeWidth={1.5}
								/>
							))}
							{modeKeys.map((m) =>
								modes[m].flows.map((flow) => (
									<path
										key={`${m}-${flow.join("-")}`}
										d={path(flow)}
										fill="none"
										className={`when-${m} flow stroke-ok`}
										strokeWidth={2}
									/>
								)),
							)}
						</svg>
						{(Object.keys(nodes) as Id[])
							.filter((id) => id !== "a")
							.map((id) => (
								<Node key={id} id={id} />
							))}
						<div className="when-normal">
							<Node id="a" />
						</div>
						<div className="when-drain">
							<Node id="a" drained />
						</div>
					</div>
					{modeKeys.map((m) => (
						<p
							key={m}
							className={`when-${m} mx-auto mt-6 max-w-lg text-center text-sm text-fg-muted`}
						>
							{modes[m].caption}
						</p>
					))}
				</figure>

				<div className="order-3">{right}</div>
			</div>
		</div>
	);
}
