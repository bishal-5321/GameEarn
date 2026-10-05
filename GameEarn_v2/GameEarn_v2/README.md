# GameEarn v2
Render root: `GameEarn_v2/earning_app` if this folder is uploaded as shown, or the folder containing `package.json`.
Build: `npm install`
Start: `npm start`

Required: `DATABASE_URL`, `SESSION_SECRET`
Email verification: `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `APP_URL`.
Email is verified once at registration; no extra verification is requested at sign-in or withdrawal.

Offers in this starter are DEMO only. Real rewards should be credited only from verified provider callbacks.
Game rewards are digital-reward requests; this starter does not distribute Steam account credentials.
