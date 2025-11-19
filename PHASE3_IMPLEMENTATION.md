# Phase 3 Implementation Summary

## Overview
Phase 3 adds scheduled scans, email alerts, multi-tenant organizations, and advanced vulnerability testing features.

## ✅ Completed Features

### 1. Prisma Schema Updates
- ✅ Added `Organization` model with slug
- ✅ Added `OrgMember` model with roles (OWNER, ADMIN, MEMBER)
- ✅ Added `ScanSchedule` model for recurring scans
- ✅ Added `AlertRule` model (optional, for org-level alerts)
- ✅ Added `AlertSettings` model for user-level alert preferences
- ✅ Added `orgId` to `Scan` model
- ✅ Added `scheduleId` to `Scan` model (optional)

### 2. Multi-Tenant Organizations
- ✅ Default organization created on user signup
- ✅ Organization switcher in dashboard navbar
- ✅ All queries scoped by `orgId`
- ✅ Session includes `orgId`
- ✅ API endpoints for org management (`/api/orgs`)

### 3. Scheduled Scans
- ✅ `POST /api/schedules` - Create schedule
- ✅ `GET /api/schedules` - List schedules for org
- ✅ `PATCH /api/schedules/[id]` - Update schedule
- ✅ `DELETE /api/schedules/[id]` - Delete schedule
- ✅ `/api/cron/run-scheduled-scans` - Cron runner endpoint
- ✅ Frequency support: daily, weekly, monthly
- ✅ Automatic next run calculation
- ✅ `/schedules` UI page with create/edit/delete

### 4. Email Alerts
- ✅ Nodemailer integration (`lib/email.ts`)
- ✅ Alert settings API (`/api/settings/alerts`)
- ✅ User-level alert preferences
- ✅ Risk level threshold (LOW/MEDIUM/HIGH)
- ✅ Email sending on scan completion
- ✅ `/settings/alerts` UI page
- ✅ HTML email templates

### 5. New Vulnerability Checks
- ✅ **Directory Listing Detection**
  - Checks common paths (/, /uploads/, /images/, /backup/)
  - Detects "Index of" patterns
  - Risk: +3 points

- ✅ **HTTP Methods Enumeration**
  - Tests PUT, DELETE, TRACE, PATCH
  - Detects enabled unsafe methods
  - Risk: +4 points

- ✅ **Mixed Content Detection**
  - Checks for HTTP resources on HTTPS pages
  - Scans HTML for insecure resource loading
  - Risk: +3 points

- ✅ **security.txt Check**
  - Checks `/.well-known/security.txt`
  - Also checks robots.txt (informational)
  - Risk: +1 point if missing

- ✅ **SQLi/XSS Probing**
  - Tests query parameters with XSS payloads
  - Tests query parameters with SQLi payloads
  - Detects reflected XSS: +6 points
  - Detects SQL errors: +5 points

- ✅ **Tech Fingerprinting**
  - Checks Server header
  - Checks X-Powered-By header
  - Checks other tech indicators
  - Risk: +1 point per exposed header

### 6. UI Updates
- ✅ `/schedules` page - Full CRUD for schedules
- ✅ `/settings/alerts` page - Alert configuration
- ✅ Dashboard org switcher
- ✅ Navigation links to new pages
- ✅ Schedule status indicators

## 📋 Setup Instructions

### 1. Install Dependencies
```bash
npm install nodemailer @types/nodemailer
```

### 2. Update Environment Variables
Add to `.env`:
```env
# Email Configuration (for alerts)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=your-email@gmail.com

# Cron Secret (for scheduled scans endpoint)
CRON_SECRET=your-secure-random-string
```

### 3. Run Database Migration
```bash
npx prisma generate
npx prisma db push
```

### 4. Set Up Cron Job
Configure an external cron service (e.g., cron-job.org, EasyCron) to call:
```
GET https://your-domain.com/api/cron/run-scheduled-scans
Authorization: Bearer YOUR_CRON_SECRET
```

Recommended frequency: Every hour or every 15 minutes.

## 🔧 API Endpoints

### Organizations
- `GET /api/orgs` - List user's organizations
- `POST /api/orgs/switch` - Switch active organization

### Schedules
- `GET /api/schedules` - List schedules for current org
- `POST /api/schedules` - Create new schedule
- `PATCH /api/schedules/[id]` - Update schedule
- `DELETE /api/schedules/[id]` - Delete schedule

### Alerts
- `GET /api/settings/alerts` - Get alert settings
- `POST /api/settings/alerts` - Update alert settings

### Cron
- `GET /api/cron/run-scheduled-scans` - Run due schedules (protected by CRON_SECRET)

## 🎯 Usage

### Creating a Scheduled Scan
1. Navigate to `/schedules`
2. Click "New Schedule"
3. Enter URL and select frequency
4. Schedule will run automatically

### Configuring Alerts
1. Navigate to `/settings/alerts`
2. Enable/disable alerts
3. Set minimum risk level
4. Configure email address
5. Save settings

### Switching Organizations
1. Use the dropdown in the navbar
2. All data (scans, schedules, stats) will switch to selected org

## 🔒 Security Notes

1. **Cron Endpoint**: Protected by `CRON_SECRET` - use a strong random string
2. **Email**: Use app passwords for Gmail, not your regular password
3. **Org Scoping**: All queries are scoped by `orgId` to prevent data leakage
4. **Session**: Includes `orgId` to maintain context

## 📊 Risk Scoring Updates

New weights added:
- Directory listing: +3
- Unsafe HTTP methods: +4
- Mixed content: +3
- Reflected XSS: +6
- SQL error exposure: +5
- Tech fingerprinting: +1 per header

Total risk levels remain:
- 0-4: LOW
- 5-9: MEDIUM
- 10+: HIGH

## 🚀 Next Steps

Potential Phase 4 features:
- Real Nmap integration for port scanning
- More advanced SQLi/XSS detection
- API rate limiting
- Webhook notifications
- Scan comparison/diff
- Custom scan profiles
- Team collaboration features

## ⚠️ Important Notes

1. **Email Setup**: Configure SMTP settings before testing alerts
2. **Cron Setup**: External cron service required for scheduled scans
3. **Performance**: New checks may increase scan time - consider async processing
4. **Rate Limiting**: Consider adding rate limits to prevent abuse

