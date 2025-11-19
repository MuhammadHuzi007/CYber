import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const session = request.cookies.get('session')
  const { pathname } = request.nextUrl

  // Public routes that don't require authentication
  const publicRoutes = ['/', '/auth/login', '/auth/register', '/api/auth']
  
  // API routes that don't require authentication
  const publicApiRoutes = ['/api/auth/login', '/api/auth/register']

  // Check if it's a public route
  if (publicRoutes.some(route => pathname === route || pathname.startsWith(route + '/'))) {
    return NextResponse.next()
  }

  // Check if it's a public API route
  if (publicApiRoutes.some(route => pathname === route)) {
    return NextResponse.next()
  }

  // Protect dashboard, scans, schedules, and settings routes
  if (pathname.startsWith('/dashboard') || 
      pathname.startsWith('/scans') || 
      pathname.startsWith('/schedules') ||
      pathname.startsWith('/settings') ||
      pathname.startsWith('/api/scans') ||
      pathname.startsWith('/api/schedules') ||
      pathname.startsWith('/api/stats') ||
      pathname.startsWith('/api/settings')) {
    if (!session) {
      if (pathname.startsWith('/api')) {
        return NextResponse.json(
          { error: 'Unauthorized' },
          { status: 401 }
        )
      }
      return NextResponse.redirect(new URL('/auth/login', request.url))
    }
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}

