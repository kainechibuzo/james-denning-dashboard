# James Denning Dashboard

A separate Express.js project for the James Denning public site, JD App Store, and protected admin dashboard.

## Stack
- Express.js API and static frontend
- Render Web Service + Render PostgreSQL
- S3-compatible object storage for uploaded release files (keeps binaries off the app filesystem)
- Admin allowlist: `kainechibuzo@gmail.com`
- Render health endpoint: `/api/health`

## Configure before first production use
Set these environment variables in Render:
- `DATABASE_URL`: internal connection string from a dedicated Render PostgreSQL database.
- `SESSION_SECRET`: long random secret (Render Blueprint generates one).
- `ADMIN_PASSWORD_HASH`: bcrypt hash of the admin password. Generate locally using `node -e "import('bcryptjs').then(async b=>console.log(await b.hash('YOUR-LONG-PASSWORD',12)))"`; never commit a plaintext password.
- `APP_ORIGIN`: public app origin.
- `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`: persistent S3-compatible object storage. Uploads deliberately fail closed until this is configured.

## Local development
1. `cp .env.example .env`
2. Fill the required environment variables.
3. `npm install`
4. `npm run dev`

The server initializes its database schema on startup. Product download links are random, stored as SHA-256 token hashes, expirable and revocable. The actual object URL is only signed for five minutes when a valid token is redeemed.

## Deployment
Use the Render Blueprint flow with `render.yaml`, or create a Node web service from this repository. Provision PostgreSQL separately and set `DATABASE_URL`. Configure persistent object storage before enabling product uploads.

## Notes
- Never commit secrets, database URLs, access keys, or password hashes.
- Render service logs and deploy status are available in the Render dashboard.
- The dashboard's public UI is being built in `public/index.html`.
