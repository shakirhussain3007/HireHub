# Job Portal (Full-Stack)
Stack: Node.js, Express, SQLite (better-sqlite3), JWT + bcrypt, Zod validation, Helmet + rate limiting, vanilla JS responsive UI.

## Run locally
    npm install && npm start      # http://localhost:3000

## API
| Method | Route | Access |
|---|---|---|
| POST | /api/auth/register, /api/auth/login | public |
| GET | /api/auth/me | logged in |
| GET | /api/jobs?q=&location=&type= , /api/jobs/:id | public |
| POST/PUT/DELETE | /api/jobs, /api/jobs/:id | employer (owner) |
| GET | /api/jobs/mine | employer |
| POST | /api/jobs/:id/apply | seeker |
| GET | /api/applications/mine | seeker |
| GET | /api/jobs/:id/applications | employer (owner) |
| PATCH | /api/applications/:id  {status} | employer (owner) |

## Deploy (Render, free/easy)
1. Push this folder to GitHub.
2. Render -> New -> Blueprint -> select repo (uses render.yaml + Dockerfile, persistent disk for SQLite).
3. JWT_SECRET is auto-generated. Live URL milega.
Alternative: `docker build -t job-portal . && docker run -p 3000:3000 -e JWT_SECRET=xyz -v jp:/data job-portal`
