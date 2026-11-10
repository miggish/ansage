import type { ComponentProps, ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * A band of the page with a dashed rule under it (ds-rule: across the frame column, with small
 * squares where it meets the guide lines).
 */
export function Section({
	children,
	className,
	inner,
	rule = true,
	bleed = false,
	...props
}: ComponentProps<"section"> & {
	inner?: string;
	/** the dashed rule under the band */
	rule?: boolean;
	/** content runs from guide line to guide line, without the side padding */
	bleed?: boolean;
	children: ReactNode;
}) {
	return (
		<section className={className} {...props}>
			<div
				className={cn(
					// min-w-0: grid children may shrink below their content (long code lines)
					"*:min-w-0",
					!bleed && "px-4 md:px-10",
					inner,
				)}
			>
				{children}
			</div>
			{rule && <div aria-hidden="true" className="ds-rule mx-0" />}
		</section>
	);
}

/** Mono, upper-case label above a heading (ds-label). */
export function Eyebrow({ children, className }: ComponentProps<"p">) {
	return <p className={cn("ds-label text-xs", className)}>{children}</p>;
}

/** A dashed box with corner brackets in the ok tone, for short facts (ds-callout). */
export function Bracketed({
	children,
	className,
}: {
	children: ReactNode;
	className?: string;
}) {
	return (
		<div data-tone="ok" className={cn("ds-callout", className)}>
			{children}
		</div>
	);
}
