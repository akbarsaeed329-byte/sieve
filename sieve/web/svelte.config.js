import adapter from '@sveltejs/adapter-static';

export default {
  kit: {
    adapter: adapter({ pages: 'build', assets: 'build', fallback: 'index.html', strict: false }),
    alias: { $c: 'src/lib/components' },
    // Inline bootstrap scripts are allowed by hash: sieve/app.py computes them from build/index.html.
    output: { bundleStrategy: 'split' }
  }
};
