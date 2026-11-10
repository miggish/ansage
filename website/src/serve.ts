// Serves dist/ and adds what static files can't do: `Accept: text/markdown` on a docs URL
// answers with its Markdown (Vary: Accept).
// `bun run start` serves a built site; `bun run dev` builds, rebuilds on every change and
// reloads the open pages.
//
// usage: bun src/serve.ts [--dev]   (PORT, default 3100)
import { watch } from "node:fs";
import { join, normalize } from "node:path";

const root = join(import.meta.dir, "..");
const dist = join(root, "dist");
const dev = Bun.argv.includes("--dev");
const port = Number(Bun.env.PORT ?? 3100);

// ---------- dev: build, watch, reload ----------

const reloads = new Set<ReadableStreamDefaultController<string>>();
let building: Promise<void> | undefined;
let again = false;

async function build() {
	if (building) {
		again = true;
		return building;
	}
	building = (async () => {
		const extract = Bun.spawn(["bun", "scripts/extract-config.mjs"], {
			cwd: root,
			stdout: "inherit",
			stderr: "inherit",
		});
		if ((await extract.exited) !== 0) return;
		const proc = Bun.spawn(["bun", "src/build.tsx"], {
			cwd: root,
			env: { ...Bun.env, ANSAGE_DEV: "1" },
			stdout: "inherit",
			stderr: "inherit",
		});
		if ((await proc.exited) === 0) {
			for (const c of reloads) c.enqueue("data: reload\n\n");
		}
	})();
	await building;
	building = undefined;
	if (again) {
		again = false;
		await build();
	}
}

if (dev) {
	await build();
	let timer: Timer | undefined;
	const onChange = (_: string, file: string | null) => {
		if (file?.includes("generated")) return; // written by the build itself
		clearTimeout(timer);
		timer = setTimeout(build, 100);
	};
	for (const dir of ["../docs", "src", "../crates/ansage/src/config.rs"]) {
		watch(join(root, dir), { recursive: true }, onChange);
	}
}

/** True when the client asks for Markdown before HTML (`Accept: text/markdown`). */
function prefersMarkdown(accept: string | null) {
	if (!accept) return false;
	const q = (type: string) => {
		const part = accept
			.split(",")
			.map((s) => s.trim())
			.find((s) => s.startsWith(type));
		if (!part) return 0;
		const m = /;\s*q=([\d.]+)/.exec(part);
		return m ? Number(m[1]) : 1;
	};
	const md = q("text/markdown");
	return md > 0 && md >= q("text/html");
}

async function file(path: string, headers: Record<string, string> = {}) {
	const f = Bun.file(path);
	if (!(await f.exists())) return undefined;
	const type: Record<string, string> = path.endsWith(".md")
		? { "Content-Type": "text/markdown; charset=utf-8" }
		: {};
	return new Response(f, { headers: { ...type, ...headers } });
}

async function serveStatic(req: Request) {
	const { pathname } = new URL(req.url);
	const path =
		normalize(decodeURIComponent(pathname)).replace(/\/+$/, "") || "/";
	if (path.includes("..")) return new Response("bad path", { status: 400 });
	const target = join(dist, path);

	if (path === "/docs" || path.startsWith("/docs/")) {
		if (!path.endsWith(".md") && prefersMarkdown(req.headers.get("accept"))) {
			const md = await file(`${target}.md`, { Vary: "Accept" });
			if (md) return md;
		}
		const page = await file(join(target, "index.html"), { Vary: "Accept" });
		if (page) return page;
	}
	return (
		(await file(target)) ??
		(await file(join(target, "index.html"))) ??
		new Response(Bun.file(join(dist, "404.html")), { status: 404 })
	);
}

Bun.serve({
	port,
	idleTimeout: 0,
	async fetch(req) {
		const { pathname } = new URL(req.url);
		if (dev && pathname === "/__reload") {
			let ctl: ReadableStreamDefaultController<string>;
			return new Response(
				new ReadableStream<string>({
					start: (c) => {
						ctl = c;
						reloads.add(c);
					},
					cancel: () => {
						reloads.delete(ctl);
					},
				}),
				{ headers: { "Content-Type": "text/event-stream" } },
			);
		}
		return serveStatic(req);
	},
});

console.log(`ansage website on http://localhost:${port}${dev ? " (dev)" : ""}`);
