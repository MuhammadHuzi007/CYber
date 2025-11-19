# Phase 2 Migration Guide

## Overview
Phase 2 adds authentication, enhanced scanning, analytics, filtering, and improved PDF reports.

## Step 1: Update Dependencies

```bash
npm install jose
```

## Step 2: Update Environment Variables

Add to your `.env` file:

```env
SESSION_SECRET="your-secret-key-change-in-production-min-32-chars"
```

Generate a secure secret:
```bash
openssl rand -base64 32
```

## Step 3: Update Database Schema

Run Prisma migrations:

```bash
npx prisma generate
npx prisma db push
```

This will:
- Add `XSS` to `FindingType` enum
- Add `INFO` to `Severity` enum
- Ensure User model is properly linked to Scan

## Step 4: Verify Authentication

1. Register a new user at `/auth/register`
2. Login at `/auth/login`
3. You should be redirected to the dashboard
4. All scans will now be associated with your user account

## Step 5: Test Enhanced Features

### Enhanced Scanning
- Headers are now checked for quality (not just presence)
- CSP is checked for unsafe directives
- XSS surface detection (inline scripts, event handlers)
- Updated risk scoring (0-4 LOW, 5-9 MEDIUM, 10+ HIGH)

### Dashboard Analytics
- View stats at the top of the dashboard
- Filter scans by risk level, URL search, date range
- All scans are user-specific

### Improved Reports
- PDF reports now include:
  - Summary section
  - Findings grouped by type
  - Severity counts
  - Better formatting

## Breaking Changes

1. **Authentication Required**: All routes except `/auth/*` now require authentication
2. **User-Specific Scans**: Scans are now tied to user accounts
3. **New Finding Types**: XSS findings are now included
4. **New Severity Level**: INFO severity for passed checks

## Troubleshooting

### Session Issues
If you're having session issues:
1. Clear browser cookies
2. Check `SESSION_SECRET` is set in `.env`
3. Restart the development server

### Database Errors
If you get Prisma errors:
1. Run `npx prisma generate`
2. Run `npx prisma db push`
3. Check your `DATABASE_URL` in `.env`

### Migration Issues
If you have existing data:
- Existing scans without `userId` will need to be migrated
- You may need to manually set `userId` for existing scans or delete them

## Next Steps

After Phase 2, consider:
- Real Nmap integration for port scanning
- Email notifications
- Scheduled scans
- API rate limiting
- More advanced XSS detection

