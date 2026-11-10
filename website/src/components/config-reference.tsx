import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";
import { formatDefault, schema } from "@/lib/config-markdown.mjs";

/** One line of a setting's details: a fixed-width label, then the value. */
function Fact({ term, children }: { term: string; children: ReactNode }) {
	return (
		<div className="flex gap-6">
			<dt className="w-20 shrink-0 text-fg-muted">{term}</dt>
			<dd>{children}</dd>
		</div>
	);
}

/**
 * The config reference, rendered from src/lib/generated/config-schema.json (generated from
 * config.rs). One native <details> per setting: opens without JavaScript, works with the
 * keyboard, and Chromium opens it for find-in-page and #:~:text= links.
 */
export function ConfigReference() {
	return (
		<>
			{schema.sections.map((section) => (
				<section key={section.id}>
					<h2 id={section.id}>{section.title}</h2>
					<div className="not-prose border">
						{section.fields.map((f) => {
							const value = formatDefault(f.default);
							const id = `${section.id}-${f.name}`;
							return (
								<details
									key={f.name}
									id={id}
									className="smooth group scroll-mt-28 border-b last:border-b-0"
								>
									<summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-3 text-sm transition-colors select-none hover:bg-surface-2/50">
										<ChevronRight className="size-3.5 shrink-0 text-fg-muted transition-transform group-open:rotate-90" />
										<code className="font-mono font-medium text-fg">
											{f.name}
										</code>
										<span className="truncate font-mono text-xs text-fg-muted">
											{f.type}
										</span>
										<span className="ms-auto shrink-0 font-mono text-xs">
											{f.required ? (
												<span data-tone="info" className="ds-tag">
													required
												</span>
											) : value ? (
												<span className="text-fg-muted">= {value}</span>
											) : (
												<span className="text-fg-subtle">optional</span>
											)}
										</span>
									</summary>
									<div className="space-y-3 border-t border-dashed bg-surface-2/40 px-4 py-4 ps-10.5 text-sm">
										{f.doc && <p className="leading-relaxed">{f.doc}</p>}
										<dl className="space-y-1.5 font-mono text-xs">
											<Fact term="Rust type">{f.rust}</Fact>
											{value && (
												<Fact term="Default">
													{f.name} = {value}
												</Fact>
											)}
											{section.table && (
												<Fact term="Where">{section.title}</Fact>
											)}
										</dl>
										<a
											href={`#${id}`}
											className="inline-block font-mono text-xs text-fg-muted underline-offset-4 hover:text-fg hover:underline"
										>
											#{id}
										</a>
									</div>
								</details>
							);
						})}
					</div>
				</section>
			))}
		</>
	);
}
