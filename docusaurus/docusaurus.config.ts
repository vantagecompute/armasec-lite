import type {Config} from '@docusaurus/types';
import {themes as prismThemes} from 'prism-react-renderer';
import {staticDir, getProjectVersion} from '@vantagecompute/docusaurus-theme';
import * as path from 'path';

// From the theme rather than hand-rolled here, so every Vantage site advertises its
// version the same way. It returns `git describe --tags --always`, so the string ALREADY
// carries its own leading `v` ("v0.1.3", or "v0.1.3-2-gb4f14ee" between tags). Do not add
// another one: doing so rendered "armasec-lite vv0.1.3" in the navbar of the built site.
const projectVersion = getProjectVersion();

// The generator parses the source with `ast` and never imports it, so it needs an
// interpreter that can merely parse Python 3.12 syntax, not one able to import the
// project's dependencies. `python3` is the right default here: this project requires
// 3.12+, not the 3.14 that vantage-mcp-infra pins, so there is no syntax this repo can
// write that a normal system `python3` cannot parse.
const pydocPython = process.env.PYDOC_PYTHON ?? 'python3';

const config: Config = {
  title: 'armasec-lite',
  tagline: `Injectable FastAPI auth via OIDC, with three dependencies (${projectVersion})`,
  favicon: 'img/favicon.ico',

  // A spoke site under the docs hub, not GitHub Pages. Authentication happens at the
  // edge: the Lambda@Edge Keycloak gateway guards all of /developer/*, so this site
  // carries no login of its own. `noIndex` because the hub is not public.
  url: 'https://docs.vantagecompute.ai',
  baseUrl: '/developer/armasec-lite/',
  noIndex: true,

  organizationName: 'vantagecompute',
  projectName: 'armasec-lite',
  deploymentBranch: 'main',
  trailingSlash: false,

  onBrokenLinks: 'throw',

  i18n: {defaultLocale: 'en', locales: ['en']},

  markdown: {
    format: 'detect',
    mermaid: true,
    hooks: {onBrokenMarkdownLinks: 'warn'},
  },

  themes: ['@docusaurus/theme-mermaid', '@vantagecompute/docusaurus-theme'],
  staticDirectories: ['static', staticDir],

  presets: [
    [
      'classic',
      {
        docs: {
          path: './docs',
          routeBasePath: '/',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/vantagecompute/armasec-lite/tree/main/docusaurus/',
        },
        blog: false,
        theme: {customCss: './src/css/custom.css'},
      },
    ],
  ],

  plugins: [
    [
      '@vantagecompute/docusaurus-plugin-pydoc',
      {
        id: 'armasec-lite',
        python: pydocPython,
        // A single instance: unlike mcp-infra's multi-package uv workspace, this project
        // is one package at the repository root, so the project root is one level up
        // from docusaurus/ rather than a path into a packages/ tree.
        projectRoot: path.join(__dirname, '..'),
        modules: [
          {module: 'armasec_lite.armasec', label: 'armasec'},
          {module: 'armasec_lite.token_security', label: 'token_security'},
          {module: 'armasec_lite.token_manager', label: 'token_manager'},
          {module: 'armasec_lite.token_decoder', label: 'token_decoder'},
          {module: 'armasec_lite.token_payload', label: 'token_payload'},
          {module: 'armasec_lite.openid_config_loader', label: 'openid_config_loader'},
          {module: 'armasec_lite.schemas', label: 'schemas'},
          {module: 'armasec_lite.jwt', label: 'jwt'},
          {module: 'armasec_lite.http', label: 'http'},
          {module: 'armasec_lite.exceptions', label: 'exceptions'},
          {module: 'armasec_lite.utilities', label: 'utilities'},
          {module: 'armasec_lite.pluggable', label: 'pluggable'},
          {module: 'armasec_lite.pluggable.hookspecs', label: 'pluggable.hookspecs'},
          {module: 'armasec_lite.pytest_extension', label: 'pytest_extension'},
        ],
        outputDir: './docs/api-reference',
      },
    ],
    [
      'docusaurus-plugin-llms',
      {
        generateLLMsTxt: true,
        generateLLMsFullTxt: true,
        docsDir: 'docs',
        title: 'armasec-lite Documentation',
        description: 'Injectable FastAPI auth via OIDC, built on the standard library.',
        includeBlog: false,
        excludeImports: true,
        removeDuplicateHeadings: true,
        generateMarkdownFiles: true,
        includeUnmatchedLast: true,
        pathTransformation: {ignorePaths: ['docs']},
      },
    ],
  ],

  customFields: {
    projectVersion,
    // No `custom-authNavbarItem` here. vdeployer registers that from its own
    // docusaurus/src/theme + OIDC contexts, not from @vantagecompute/docusaurus-theme,
    // so referencing it without that local implementation fails the build with
    // "No NavbarItem component found for type". This site has no gated content, so it
    // has no login. Port vdeployer's src/{theme,contexts,components} if that changes.
  },

  themeConfig: {
    navbar: {
      // The version belongs in the tagline, which is where every other Vantage site
      // carries it. A navbar title that grows a git-describe suffix between releases
      // reflows the header on every commit.
      title: 'armasec-lite',
      // Served from static/img rather than the S3 branding bucket: the SVG is a few KB,
      // renders crisply at any zoom, and does not make the header wait on a third-party
      // request. No `srcDark`: the theme pins the navbar background to #18123B in both
      // colour modes, so the wordmark's white glyphs read the same either way, and a
      // second asset would only be a second thing to keep in sync.
      logo: {
        alt: 'Vantage Compute',
        src: 'img/vantage-logo-color.svg',
        href: 'https://docs.vantagecompute.ai',
        target: '_self',
      },
      items: [
        {type: 'docSidebar', sidebarId: 'docsSidebar', position: 'left', label: 'Docs'},
        {to: '/api-reference/', label: 'API Reference', position: 'left'},
        {
          href: 'https://github.com/vantagecompute/armasec-lite',
          label: 'GitHub',
          position: 'right',
          className: 'github-button',
        },
      ],
    },
    footer: {
      style: 'dark',
      logo: {
        alt: 'Vantage Compute Logo',
        src: 'https://vantage-compute-public-assets.s3.us-east-1.amazonaws.com/branding/vantage-logo-text-white-horz.png',
        href: 'https://vantagecompute.ai',
      },
      links: [
        {
          title: 'Documentation',
          items: [
            {label: 'Overview', to: '/'},
            {label: 'Installation', to: '/installation'},
            {label: 'Quickstart', to: '/quickstart'},
            {label: 'Migration', to: '/migration'},
            {label: 'Architecture', to: '/architecture/'},
            {label: 'Security', to: '/security/'},
            {label: 'API Reference', to: '/api-reference/'},
            {label: 'Contributing', to: '/contributing'},
          ],
        },
        {
          title: 'Community',
          items: [
            {label: 'Issues', href: 'https://github.com/vantagecompute/armasec-lite/issues'},
            {label: 'Support', href: 'https://vantagecompute.ai/support'},
          ],
        },
        {
          title: 'More',
          items: [
            {label: 'GitHub', href: 'https://github.com/vantagecompute/armasec-lite'},
            {label: 'Vantage Compute', href: 'https://vantagecompute.ai'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Vantage Compute.`,
    },
    codeBlock: {showCopyButton: true},
    prism: {
      theme: prismThemes.vsLight,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['shell-session', 'python', 'bash', 'json', 'yaml'],
    },
    tableOfContents: {minHeadingLevel: 2, maxHeadingLevel: 4},
  },
};

export default config;
