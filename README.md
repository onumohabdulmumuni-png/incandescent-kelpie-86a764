# ANUCHO

ANUCHO is a browser-based point-of-sale and patent portfolio workspace. The
deployed app uses Supabase Auth for email/password and phone/password accounts,
Supabase Postgres for workspace data, and Supabase Realtime to keep staff views
in sync. Netlify serves the static web interface.

The original SQLite Node server remains available for its existing integration
tests, but it is not used by the Supabase deployment.

## Features

- POS checkout with stock validation and decrement, configurable tax, cash
  tender/change, recorded payment methods, receipts, and recent-sales reporting.
- Product catalog with SKU/barcode, price, on-hand quantity, and patent links.
- Patent, supplier, team, showroom, report, and workspace settings.
- Owner, editor, and read-only reviewer roles.
- Owner-created team accounts with one-time temporary passwords.
- Private-by-default showroom collections and public showroom data.
- CSV patent and sales exports with spreadsheet formula injection protection.
- Authenticated real-time updates across staff devices.

Passkey/biometric sign-in is not included in this Supabase version, as requested.
Phone registration/sign-in requires enabling phone auth and configuring an SMS
provider in Supabase. The POS records payment tender types only; it does not
process card payments.

## Run locally

1. Install Node.js 24 LTS or later.
2. Create a Supabase project and copy `.env.example` to `.env.local`.
3. Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` to the project URL and
   **publishable** key. Never put a service-role key in the browser or a `VITE_`
   variable.
4. Install dependencies with `npm install`.
5. Apply the database migration and deploy the API function as described below.
6. Allow `http://localhost:5173` in `ANUCHO_ALLOWED_ORIGINS` for the Edge
   Function, then run `npm run dev`.

The first account created becomes the workspace owner. Use email confirmation
or phone OTP as configured in Supabase Auth. Review your Supabase Auth settings
for password policy, rate limits, email delivery, phone/SMS provider, and
allowed redirect URLs before inviting staff.

## Deploy Supabase

Install the Supabase CLI and sign in, then:

1. Create a Supabase project and note its project reference.
2. Link this folder to the project with `supabase link --project-ref <project-ref>`.
3. Apply the schema with `supabase db push`.
4. Configure the app's allowed origins (local development and the exact
   Netlify site URL) and deploy the function:

   ```powershell
   supabase secrets set ANUCHO_ALLOWED_ORIGINS="http://localhost:5173,https://gentle-stroopwafel-dfde99.netlify.app"
   supabase functions deploy api
   ```

The function uses Supabase's server-side `SUPABASE_URL`,
`SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` environment values. The
service-role key must remain server-side and must never be copied into Netlify
build variables or browser code.

## Deploy Netlify

1. Connect the project repository to Netlify. The site you shared is
   `https://gentle-stroopwafel-dfde99.netlify.app`.
2. The included `netlify.toml` sets the build command to `npm run build`, the
   publish directory to `dist`, and Node.js 24.
3. In the Netlify site environment settings, add `VITE_SUPABASE_URL` and
   `VITE_SUPABASE_ANON_KEY` using the Supabase project URL and publishable key.
   Never add the service-role key. These are build-time variables, so trigger a
   new deploy after adding or changing them. The current site displays a
   configuration warning until those values are present in its build.
4. Add `https://gentle-stroopwafel-dfde99.netlify.app` to Supabase
   Auth's site URL/redirect allow list and to `ANUCHO_ALLOWED_ORIGINS`. Redeploy
   the Edge Function if the allowed origins changed.

For a custom domain, use its exact HTTPS origin in both Supabase Auth settings
and `ANUCHO_ALLOWED_ORIGINS`, then rebuild the Netlify site.

## Existing SQLite data

The Supabase database starts empty. Existing records in `data/anucho.db` are
not uploaded or converted automatically. Keep a private, encrypted backup of
that database before switching. Plan and verify a deliberate import before
using this deployment for live store data; user passwords and sessions cannot
be copied from the old SQLite authentication system.

## Development checks

- `npm run build` builds the static Netlify site.
- `npm test` runs the legacy Node/SQLite integration tests; it does not
  validate a connected Supabase project.
- Apply and test SQL migrations against a non-production Supabase project
  before using them for real store data.
