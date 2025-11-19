import { NextRequest, NextResponse } from 'next/server'
import { verifyUser } from '@/lib/auth'
import { createSession } from '@/lib/session'
import { z } from 'zod'

const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
})

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { email, password } = loginSchema.parse(body)

    const user = await verifyUser(email, password)
    if (!user) {
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      )
    }

    // Create session
    await createSession(user.id)

    return NextResponse.json({
      id: user.id,
      email: user.email,
    })
  } catch (error) {
    console.error('Login error:', error)
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.errors[0].message },
        { status: 400 }
      )
    }
    return NextResponse.json(
      { error: 'Failed to login' },
      { status: 500 }
    )
  }
}

