# Vulnerability Scanner Dashboard

A web application for scanning websites for common security vulnerabilities including XSS, open ports, missing security headers, and SSL issues.

## Features

- 🔍 **Security Scanning**: Scan URLs for common vulnerabilities
  - HTTP/Security Header checks (CSP, X-Frame-Options, etc.)
  - SSL/HTTPS validation
  - Port scanning (basic implementation)
- 📊 **Risk Scoring**: Automatic risk score calculation (Low/Medium/High)
- 📜 **Scan History**: View all past scans with details
- 📄 **PDF Reports**: Download detailed PDF reports of scan results
- 🔐 **User Authentication**: Register and login to track your scans

## Tech Stack

- **Frontend**: Next.js 14 (App Router), React, TypeScript, Tailwind CSS
- **Backend**: Next.js API Routes
- **Database**: PostgreSQL with Prisma ORM
- **PDF Generation**: jsPDF

## Getting Started

### Prerequisites

- Node.js 18+ installed
- PostgreSQL database running
- npm or yarn package manager

### Installation

1. **Clone the repository** (or navigate to the project directory)

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Set up environment variables**:
   Create a `.env` file in the root directory:
   ```env
   DATABASE_URL="postgresql://user:password@localhost:5432/vulnerability_scanner?schema=public"
   ```

4. **Set up the database**:
   ```bash
   npx prisma generate
   npx prisma db push
   ```

5. **Run the development server**:
   ```bash
   npm run dev
   ```

6. **Open your browser**:
   Navigate to [http://localhost:3000](http://localhost:3000)

## Project Structure

```
├── app/
│   ├── api/
│   │   ├── auth/          # Authentication endpoints
│   │   └── scans/         # Scan endpoints
│   ├── auth/              # Login/Register pages
│   ├── scans/[id]/        # Scan details page
│   ├── layout.tsx         # Root layout
│   ├── page.tsx           # Dashboard
│   └── globals.css        # Global styles
├── lib/
│   ├── auth.ts            # Authentication utilities
│   ├── pdf.ts             # PDF generation
│   ├── prisma.ts          # Prisma client
│   └── scanner.ts         # Scanning logic
├── prisma/
│   └── schema.prisma      # Database schema
└── package.json
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user

### Scans
- `POST /api/scans` - Create and run a new scan
- `GET /api/scans` - Get all scans (with pagination)
- `GET /api/scans/[id]` - Get scan details
- `GET /api/scans/[id]/report` - Download PDF report

## Security Checks

The scanner performs the following checks:

1. **Security Headers**:
   - Content-Security-Policy
   - X-Frame-Options
   - X-Content-Type-Options
   - Strict-Transport-Security
   - Referrer-Policy

2. **SSL/HTTPS**:
   - Checks if URL uses HTTPS
   - Validates SSL connection

3. **Port Scanning**:
   - Checks for commonly exploited ports (21, 22, 3306, etc.)
   - Note: Currently uses mock implementation for MVP

## Risk Score Calculation

- Missing critical header: +2 points
- Using HTTP (no HTTPS): +3 points
- Suspicious port open: +2 points
- Other issues: +0.5-1 points

**Risk Levels**:
- 0-2: Low
- 3-5: Medium
- 6+: High

## Development

### Database Management

```bash
# Generate Prisma Client
npm run db:generate

# Push schema changes to database
npm run db:push

# Open Prisma Studio (database GUI)
npm run db:studio
```

### Building for Production

```bash
npm run build
npm start
```

## Notes

- The port scanning feature uses a mock implementation for the MVP. Replace with actual Nmap integration for production use.
- Authentication is basic for MVP. Consider implementing proper session management (NextAuth.js) for production.
- The scanner runs synchronously. Consider implementing background jobs for better scalability.

## License

MIT

