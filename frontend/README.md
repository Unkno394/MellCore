# MellCore Dashboard

The React/Vite dashboard talks only to the MellCore management API. It never connects to `hf-center`, and no control token or SSH credential is exposed to browser code.

## Development

Copy `.env.example` to `.env.local` if the backend is not listening on `http://127.0.0.1:8080`, then run `npm run dev`. Vite proxies `/api` and `/health` to `MELLCORE_API_PROXY_TARGET`, keeping browser requests same-origin during development.

Only non-secret browser configuration belongs in variables prefixed with `VITE_`; Vite embeds those values into the client bundle. `MELLCORE_API_PROXY_TARGET` is consumed only by `vite.config.ts`.

## Production

Run `npm run build` and serve `dist/` as static files. The production reverse proxy should:

- fall back to `index.html` for client routes such as `/reset-password` and `/verify-email`;
- proxy `/api/*` and `/health/*` to the Rust backend;
- terminate TLS and keep the frontend and management API on the same public origin.

The Vite development proxy is not part of the production server.
