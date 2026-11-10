import { Copy } from "lucide-react";

/** The install command with a copy button (the only part that needs site.js). */
export function InstallCommand({ command }: { command: string }) {
	return (
		<div className="flex items-center gap-3 border border-terminal-border bg-terminal px-4 py-3.5 font-mono text-sm text-terminal-foreground">
			<span className="select-none text-terminal-accent">$</span>
			<code className="no-scrollbar min-w-0 flex-1 overflow-x-auto whitespace-nowrap">
				{command}
			</code>
			<button
				type="button"
				data-copy-text={command}
				aria-label="Copy the install command"
				className="shrink-0 text-terminal-muted transition-colors hover:text-terminal-foreground"
			>
				<Copy className="size-4" />
			</button>
		</div>
	);
}
