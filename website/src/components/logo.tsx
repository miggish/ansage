import type { SVGProps } from "react";

/** ansage's mark: a post horn (📯) on a brass tile. Same drawing as the favicon in build.tsx. */
export function Logo(props: SVGProps<SVGSVGElement>) {
	return (
		<svg viewBox="0 0 128 128" fill="none" aria-hidden="true" {...props}>
			<rect width="128" height="128" rx="32" fill="#EDB24D" />
			<g
				stroke="black"
				strokeWidth="6"
				strokeLinecap="round"
				strokeLinejoin="round"
			>
				<path d="M75.5785 69.0506C80.8804 78.2338 77.734 89.9763 68.5508 95.2783C59.3676 100.58 47.625 97.4338 42.3231 88.2506C37.0212 79.0674 40.1676 67.3248 49.3508 62.0229C58.534 56.721 70.2765 59.8674 75.5785 69.0506Z" />
				<path d="M21.638 78.0229L67.826 51.3562M15.6667 74.0803L22.0667 85.1655" />
			</g>
			<path
				d="M62.9214 49.2612C74.8826 41.5342 83.0821 30.8472 87.5197 17.2C96.8687 26.993 103.447 38.3861 107.253 51.3791C93.2154 48.3986 79.8604 50.156 67.188 56.6513L62.9214 49.2612Z"
				fill="black"
			/>
		</svg>
	);
}
