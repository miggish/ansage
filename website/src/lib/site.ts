export const appName = "ansage";

export const gitConfig = {
	user: "miggish",
	repo: "ansage",
	branch: "main",
};

export const repoUrl = `https://github.com/${gitConfig.user}/${gitConfig.repo}`;

// the latest release, shown in the banner and on the home page
export const release = {
	version: "v0.4.0",
	url: `${repoUrl}/releases/tag/v0.4.0`,
	// what is new, for the banner
	highlights: "filters, BGP roles (RFC 9234) and ansage test",
};
