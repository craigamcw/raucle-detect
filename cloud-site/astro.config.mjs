import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://cloud.raucle.com',
  output: 'static',
  build: {
    inlineStylesheets: 'auto',
  },
});
