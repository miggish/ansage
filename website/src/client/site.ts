// The site's only script. Everything else (tabs, menus, the config reference) is HTML and CSS.
// - theme toggle: sets data-theme="light|dark" on <html> and
//   stores it; without a choice the CSS follows the system
// - copy buttons: code blocks, the install command, a page's Markdown
// - search: Pagefind's UI, loaded the first time the dialog opens

const root = document.documentElement;

function isDark() {
	if (root.dataset.theme === "dark") return true;
	if (root.dataset.theme === "light") return false;
	return matchMedia("(prefers-color-scheme: dark)").matches;
}

function toggleTheme() {
	const next = isDark() ? "light" : "dark";
	root.dataset.theme = next;
	try {
		localStorage.setItem("theme", next);
	} catch {
		// private mode: the choice lasts for this page only
	}
}

async function copy(button: HTMLElement, text: string) {
	await navigator.clipboard.writeText(text);
	button.dataset.copied = "";
	const label = button.getAttribute("aria-label");
	button.setAttribute("aria-label", "Copied");
	setTimeout(() => {
		delete button.dataset.copied;
		if (label) button.setAttribute("aria-label", label);
	}, 1500);
}

let searchLoaded: Promise<void> | undefined;

function loadSearch() {
	searchLoaded ??= new Promise<void>((resolve, reject) => {
		const css = document.createElement("link");
		css.rel = "stylesheet";
		css.href = "/pagefind/pagefind-ui.css";
		document.head.append(css);
		const script = document.createElement("script");
		script.src = "/pagefind/pagefind-ui.js";
		script.onload = () => {
			// biome-ignore lint/suspicious/noExplicitAny: Pagefind's UI has no types
			const { PagefindUI } = window as any;
			new PagefindUI({
				element: "#search-ui",
				showSubResults: true,
				showImages: false,
				resetStyles: false,
			});
			resolve();
		};
		script.onerror = () =>
			reject(new Error("search is not built (bun run build)"));
		document.head.append(script);
	});
	return searchLoaded;
}

async function openSearch() {
	const dialog = document.getElementById("search") as HTMLDialogElement | null;
	if (!dialog || dialog.open) return;
	dialog.showModal();
	await loadSearch();
	dialog.querySelector<HTMLInputElement>("input")?.focus();
}

document.addEventListener("click", (event) => {
	const target = event.target as HTMLElement;
	const button = target.closest<HTMLElement>(
		"[data-theme-toggle],[data-copy-code],[data-copy-text],[data-copy-url],[data-search-open]",
	);
	if (target instanceof HTMLDialogElement) target.close(); // a click on the backdrop
	if (!button) return;
	if ("themeToggle" in button.dataset) toggleTheme();
	if ("searchOpen" in button.dataset) openSearch();
	if ("copyText" in button.dataset) copy(button, button.dataset.copyText ?? "");
	if ("copyCode" in button.dataset) {
		const code = button.parentElement?.querySelector("pre")?.textContent ?? "";
		copy(button, code);
	}
	if (button.dataset.copyUrl) {
		fetch(button.dataset.copyUrl)
			.then((res) => res.text())
			.then((text) => copy(button, text));
	}
});

document.addEventListener("keydown", (event) => {
	const typing = (event.target as HTMLElement).closest(
		"input, textarea, [contenteditable]",
	);
	const shortcut =
		(event.key === "k" && (event.metaKey || event.ctrlKey)) ||
		(event.key === "/" && !typing);
	if (shortcut) {
		event.preventDefault();
		openSearch();
	}
});
