# Web Attack Vector Base — deploy to Render

This is your full app (all 42 vectors, the 8 hands-on labs, matrix rain background,
ticker, attack-flow diagrams — nothing trimmed) wrapped in a proper Vite build so a
static host like Render can actually serve it.

## Why the blank page happened

Render (and any static host) just serves files as-is. A raw `.jsx` file with
`import` statements and JSX syntax isn't something a browser can run directly —
it needs to be compiled into plain JS first. That compile step is what was missing.

## Deploy to Render (Static Site)

1. Push this whole folder to a GitHub repo (or upload it directly if your Render
   plan supports that).
2. In Render, create a **New → Static Site** (not a Web Service — there's no server
   here, it's a pure static bundle).
3. Connect the repo and set:
   - **Build Command:** `npm install && npm run build`
   - **Publish Directory:** `dist`
4. Deploy. Render will run the build and serve the `dist/` folder.

If you already have a Render service pointed at this repo showing a blank page,
just update its Build Command and Publish Directory to the values above and
trigger a redeploy — no need to recreate the service.

## Run locally first (optional, recommended)

```
npm install
npm run dev
```

Opens a local dev server so you can check everything renders correctly before
pushing to Render.

## Project structure

```
index.html          — entry point Vite/Render actually loads
src/main.jsx         — mounts your VectorBase component into the page
src/VectorBase.jsx    — your full app, unchanged
package.json         — dependencies (react, react-dom, lucide-react) + build script
vite.config.js        — Vite + React plugin config
```
