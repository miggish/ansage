# ansage website

The pages are MDX in the repo's `docs/`; this folder builds them into a static site in
`dist/`. No framework: Bun, MDX, React only at build time (to render JSX to HTML), Tailwind,
Shiki, Pagefind. The browser gets HTML, one stylesheet and one small script (theme toggle,
copy buttons, search).

```sh
bun install
bun run dev              # http://localhost:3100, rebuilds and reloads on every change
bun run build            # -> dist/
bun run start            # serves dist/ (PORT, default 3100)
bun run check:md         # against a running site: llms.txt, .md pages, no leftover JSX
bun run lint             # Biome (bun run format applies fixes)
```

| file                 | what                                                                                |
| -------------------- | ----------------------------------------------------------------------------------- |
| `src/content.ts`     | reads `docs/`: `NN-` prefixes set the order and are left out of URLs and names      |
| `src/mdx.ts`         | MDX -> component: GFM, Shiki (light + dark), heading ids, table of contents         |
| `src/markdown.ts`    | the Markdown form of every page for agents; a component without one fails the build |
| `src/components/`    | the MDX components, the page shell (header, banner, search), the home page parts    |
| `src/pages/`         | home, docs page, 404                                                                |
| `src/client/site.ts` | the only script                                                                     |
| `src/styles.css`     | Tailwind + the miggi. design system, ansage tokens, the CSS-only tabs and diagram   |
| `src/build.tsx`      | builds everything into `dist/`, runs Tailwind and Pagefind                          |
| `src/serve.ts`       | serves `dist/`; `Accept: text/markdown` on docs URLs                                |

For agents: every page is also `/docs/<page>.md`, `/llms.txt` lists them, `/llms-full.txt` has
all of them, and `Accept: text/markdown` on a docs URL returns the Markdown (needs `serve.ts`).

A new MDX component needs both forms: the HTML one in `src/components/mdx.tsx` and the Markdown
one in `src/markdown.ts`; the build refuses a component that has only one.

The look comes from the miggi. design system (`@miggish/design` on npm): its tokens (`bg`,
`fg`, `line`, `ok`, …) and `ds-*` classes. A new version of it: `bun update @miggish/design`.
