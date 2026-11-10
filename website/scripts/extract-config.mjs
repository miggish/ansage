// Reads the doc comments and serde attributes of ansage's config structs and writes
// src/lib/generated/config-schema.json, which the config reference page renders. Runs before
// `bun run dev` and `bun run build`, so the reference always matches crates/ansage/src/config.rs.
//
// usage: bun scripts/extract-config.mjs [path/to/config.rs]
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(
	process.argv[2] ?? join(here, "../../crates/ansage/src/config.rs"),
	"utf8",
);

// values that the default functions return through constants
const known = {
	"ansage_netlink::RT_TABLE_MAIN": 254,
	DEFAULT_CONTROL_SOCKET: "/run/ansage/ansage.sock",
	"vec![Family::Ipv4, Family::Ipv6]": ["ipv4", "ipv6"],
};

function defaultFn(name) {
	const m = src.match(
		new RegExp(`fn ${name}\\(\\)[^{]*\\{\\s*([^}]*?)\\s*\\}`),
	);
	if (!m) return undefined;
	const body = m[1].replace(/\.into\(\)$/, "");
	if (/^\d+$/.test(body)) return Number(body);
	return known[body];
}

function typeDefault(type) {
	if (type === "bool") return false;
	if (/^u\d+$/.test(type)) return 0;
	if (type.startsWith("Vec<")) return [];
	if (type === "ImportPolicy") return "none";
	if (type === "ExportPolicy") return "own";
	return undefined;
}

function tomlType(type) {
	const inner = type.replace(/^Option<(.*)>$/, "$1");
	if (/^u\d+$/.test(inner)) return "integer";
	if (inner === "bool") return "boolean";
	if (inner.startsWith("Vec<")) return "array";
	if (inner === "ImportPolicy") return '"none" | "all"';
	if (inner === "ExportPolicy") return '"own"';
	return "string";
}

function struct(name) {
	const start = src.indexOf(`pub struct ${name} {`);
	const end = src.indexOf("\n}", start);
	const lines = src.slice(start, end).split("\n").slice(1);
	const fields = [];
	let doc = [];
	let serde = "";
	for (const raw of lines) {
		const line = raw.trim();
		if (line.startsWith("///")) doc.push(line.slice(3).trim());
		else if (line.startsWith("#[serde(")) serde += line;
		else if (line.startsWith("pub ")) {
			const [, field, type] = line.match(/^pub (\w+): (.+),$/);
			const rename = serde.match(/rename = "(\w+)"/)?.[1];
			const fnName = serde.match(/default = "(\w+)"/)?.[1];
			const hasDefault = /default[,)]/.test(serde);
			const optional = type.startsWith("Option<");
			fields.push({
				name: rename ?? field,
				type: tomlType(type),
				rust: type,
				required: !optional && !fnName && !hasDefault,
				default: fnName
					? defaultFn(fnName)
					: hasDefault
						? typeDefault(type)
						: undefined,
				doc: doc.join(" ").replace(/\\([[\]])/g, "$1"),
			});
			doc = [];
			serde = "";
		}
	}
	return fields;
}

const sections = [
	{
		id: "global",
		title: "Global settings",
		table: null,
		fields: struct("Config").filter(
			(f) => !["kernel", "neighbor"].includes(f.name),
		),
	},
	{
		id: "neighbor",
		title: "[[neighbor]]",
		table: "neighbor",
		fields: struct("Neighbor"),
	},
	{
		id: "kernel",
		title: "[kernel]",
		table: "kernel",
		fields: struct("Kernel"),
	},
];

const out = join(here, "../src/lib/generated/config-schema.json");
mkdirSync(dirname(out), { recursive: true });
const json = JSON.stringify(
	{ source: "crates/ansage/src/config.rs", sections },
	null,
	"\t",
);
writeFileSync(out, `${json}\n`);
console.log(
	`config-schema.json: ${sections.map((s) => `${s.id} ${s.fields.length}`).join(", ")}`,
);
