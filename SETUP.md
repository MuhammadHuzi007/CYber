# Quick Setup Guide

## Step 1: Install Dependencies

```bash
npm install
```

## Step 2: Set Up Database

1. Make sure PostgreSQL is running on your machine
2. Create a database (or use an existing one):
   ```sql
   CREATE DATABASE vulnerability_scanner;
   ```

3. Create a `.env` file in the root directory:
   ```env
   DATABASE_URL="postgresql://username:password@localhost:5432/vulnerability_scanner?schema=public"
   ```
   Replace `username` and `password` with your PostgreSQL credentials.

## Step 3: Initialize Database Schema

```bash
npx prisma generate
npx prisma db push
```

This will:
- Generate the Prisma Client
- Create all tables in your database

## Step 4: Run the Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Step 5: Test the Application

1. Go to the dashboard
2. Enter a URL (e.g., `https://example.com`)
3. Click "Scan"
4. Wait for the scan to complete
5. View the results and download a PDF report

## Optional: View Database

You can use Prisma Studio to view and manage your database:

```bash
npm run db:studio
```

This opens a GUI at [http://localhost:5555](http://localhost:5555)

## Troubleshooting

### Database Connection Issues

- Make sure PostgreSQL is running
- Verify your `DATABASE_URL` in `.env` is correct
- Check that the database exists

### Port Already in Use

If port 3000 is already in use, you can change it:

```bash
PORT=3001 npm run dev
```

### Prisma Client Not Found

If you get errors about Prisma Client:

```bash
npx prisma generate
```

## Next Steps

- For production, consider:
  - Adding proper session management (NextAuth.js)
  - Implementing real Nmap integration for port scanning
  - Adding rate limiting
  - Setting up proper error logging
  - Adding email notifications for scan completion

