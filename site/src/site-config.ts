import type { SiteConfig } from '@mcptoolshop/site-theme';

export const config: SiteConfig = {
  title: 'NullOut',
  description: 'MCP server that finds and safely removes undeletable files on Windows',
  logoBadge: 'NO',
  brandName: 'NullOut',
  repoUrl: 'https://github.com/mcp-tool-shop-org/nullout',
  pypiUrl: 'https://pypi.org/project/nullout-mcp/',
  footerText: 'MIT Licensed — built by <a href="https://mcp-tool-shop.github.io/" style="color:var(--color-muted);text-decoration:underline">MCP Tool Shop</a>',

  hero: {
    badge: 'Open source',
    headline: 'NullOut',
    headlineAccent: 'remove the unremovable.',
    description: 'MCP server that finds and safely removes undeletable files on Windows — reserved device names, trailing dots, overlong paths.',
    primaryCta: { href: '#usage', label: 'Get started' },
    secondaryCta: { href: '#features', label: 'Learn more' },
    previews: [
      { label: 'Install', code: 'pip install nullout-mcp' },
      { label: 'Configure', code: 'set NULLOUT_ROOTS=C:\\Users\\me\\Downloads' },
      { label: 'Run', code: 'nullout-mcp' },
    ],
  },

  sections: [
    {
      kind: 'features',
      id: 'features',
      title: 'Features',
      subtitle: 'Safe filesystem cleanup for Windows edge cases.',
      features: [
        { title: 'Scan', desc: 'Detect reserved device names (CON, PRN, NUL, COM1-COM9), trailing dots/spaces, and overlong paths across allowlisted directories.' },
        { title: 'Plan', desc: 'Generate HMAC-signed confirmation tokens bound to file identity (volume serial + file ID) with automatic TOCTOU protection.' },
        { title: 'Delete', desc: 'Remove hazardous entries via the \\\\?\\ extended path namespace. Files only — empty directories only. No raw paths accepted.' },
      ],
    },
    {
      kind: 'data-table',
      id: 'tools',
      title: 'MCP Tools',
      subtitle: '7 tools — 6 read-only, 1 destructive.',
      columns: ['Tool', 'Type', 'Purpose'],
      rows: [
        ['list_allowed_roots', 'read-only', 'Show configured scan roots'],
        ['scan_reserved_names', 'read-only', 'Find hazardous entries in a root'],
        ['get_finding', 'read-only', 'Get full details for a finding'],
        ['plan_cleanup', 'read-only', 'Generate deletion plan with confirmation tokens'],
        ['delete_entry', 'destructive', 'Delete a file or empty directory (requires token)'],
        ['who_is_using', 'read-only', 'Identify processes locking a file (Restart Manager)'],
        ['get_server_info', 'read-only', 'Server metadata, policies, and capabilities'],
      ],
    },
    {
      kind: 'code-cards',
      id: 'usage',
      title: 'Usage',
      cards: [
        { title: 'Install', code: 'pip install nullout-mcp' },
        { title: 'Configure', code: '# Set allowlisted scan roots\nset NULLOUT_ROOTS=C:\\Users\\me\\Downloads;C:\\temp\\cleanup\n\n# Token signing secret\nset NULLOUT_TOKEN_SECRET=your-random-secret-here' },
      ],
    },
    {
      kind: 'features',
      id: 'safety',
      title: 'Safety Model',
      subtitle: 'Defense in depth for filesystem operations.',
      features: [
        { title: 'Root Confinement', desc: 'All operations confined to directories you explicitly allowlist via NULLOUT_ROOTS. Path traversal attempts are resolved and rejected.' },
        { title: 'Reparse Deny-All', desc: 'Junctions, symlinks, and mount points are detected and never traversed or deleted.' },
        { title: 'Identity Binding', desc: 'Confirmation tokens are HMAC-SHA256 signed and bound to volume serial + file ID. Any change between scan and delete is rejected.' },
      ],
    },
  ],
};
