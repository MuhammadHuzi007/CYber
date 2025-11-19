import { SignJWT, jwtVerify } from 'jose'
import { cookies } from 'next/headers'

const secretKey = process.env.SESSION_SECRET || 'your-secret-key-change-in-production'
const encodedKey = new TextEncoder().encode(secretKey)

export async function createSession(userId: string) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days

  const session = await new SignJWT({ userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .sign(encodedKey)

  cookies().set('session', session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    expires: expiresAt,
    path: '/',
  })

  return session
}

export async function getSession(): Promise<{ userId: string } | null> {
  const session = cookies().get('session')?.value

  if (!session) {
    return null
  }

  try {
    const { payload } = await jwtVerify(session, encodedKey)
    return { userId: payload.userId as string }
  } catch (error) {
    return null
  }
}

export async function deleteSession() {
  cookies().delete('session')
}

