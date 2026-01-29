# Encrypted P2P Chat - Frontend

SolidJS frontend with Vite, TypeScript, and Tailwind CSS v4.

## Requirements

- **Node.js 20.19+ or 22.12+** (required for Vite 7)

## Tech Stack

- **SolidJS 1.9.10** - Fine-grained reactivity
- **TypeScript 5.9** - Type safety
- **Vite 7** - Build tool (ESM only, requires Node 20.19+)
- **Tailwind CSS v4.1** - Utility-first CSS (stable release)
- **@solidjs/router** - Client-side routing
- **@tanstack/solid-query 5.90** - Data fetching and caching
- **nanostores 1.1** - State management

## Development

```bash
npm install
npm run dev
```

Frontend runs on http://localhost:3000

## Build

```bash
npm run build
```

Output in `dist/` directory.

## SolidJS Routing

Unlike React Router, SolidJS uses:
- `<A>` component for navigation (not `<Link>`)
- `useNavigate()` for programmatic navigation
- `useParams()` for route parameters
- `useSearchParams()` for query parameters

## Environment Variables

Copy `.env.example` to `.env` and configure:

- `VITE_API_URL` - Backend API URL
- `VITE_WS_URL` - WebSocket URL
- `VITE_RP_ID` - WebAuthn Relying Party ID
