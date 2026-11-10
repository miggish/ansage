/** Joins class names, skipping false, null and undefined. */
export function cn(...classes: (string | false | null | undefined)[]) {
	return classes.filter(Boolean).join(" ");
}
