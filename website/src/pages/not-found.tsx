import { Document, SiteHeader } from "@/components/layout";

export function NotFoundPage({ dev }: { dev?: boolean }) {
	return (
		<Document
			title="Not found · ansage"
			description="This page does not exist."
			dev={dev}
		>
			<SiteHeader url="/404" />
			<div className="ds-frame">
				<main className="flex flex-1 flex-col items-start justify-center gap-4 px-4 py-24 md:px-10">
					<span data-tone="muted" className="ds-tag">
						404
					</span>
					<h1 className="text-4xl font-semibold tracking-tight">
						No route to this page.
					</h1>
					<p className="text-fg-muted">
						It may have moved. The{" "}
						<a
							href="/docs"
							className="text-fg underline decoration-fg-subtle underline-offset-4 hover:decoration-fg"
						>
							docs
						</a>{" "}
						list every page.
					</p>
				</main>
			</div>
		</Document>
	);
}
