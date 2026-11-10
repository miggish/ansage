export const appName = "ansage";

export const gitConfig = {
	user: "miggish",
	repo: "ansage",
	branch: "main",
};

export const repoUrl = `https://github.com/${gitConfig.user}/${gitConfig.repo}`;

// the latest release, shown in the banner and on the home page
export const release = {
	version: "v0.3.0",
	url: `${repoUrl}/releases/tag/v0.3.0`,
	// what is new, for the banner
	highlights: "IPv4 routes over IPv6 sessions (RFC 8950)",
};
