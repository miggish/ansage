// The Markdown form of the generated config reference, for the agent-facing `.md` pages
// (the HTML page renders the same schema with src/components/config-reference.tsx).
import schema from "./generated/config-schema.json" with { type: "json" };

export { schema };

/** `90`, `"none"`, `["ipv4", "ipv6"]`; empty when there is no default. */
export function formatDefault(value) {
	return value === undefined ? "" : JSON.stringify(value).replaceAll(",", ", ");
}

const cell = (text) => text.replaceAll("|", "\\|").replaceAll("\n", " ");

export function configMarkdown(level = 2) {
	const hashes = "#".repeat(level);
	return schema.sections
		.map((section) => {
			const rows = section.fields.map(
				(f) =>
					`| \`${f.name}\` | ${cell(f.type)} | ${f.required ? "required" : cell(formatDefault(f.default) ? `\`${formatDefault(f.default)}\`` : "-")} | ${cell(f.doc || "-")} |`,
			);
			return [
				`${hashes} ${section.title}`,
				"",
				"| setting | type | default | meaning |",
				"|---|---|---|---|",
				...rows,
			].join("\n");
		})
		.join("\n\n");
}
