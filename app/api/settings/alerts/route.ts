import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { getSession } from '@/lib/session'
import { z } from 'zod'

const alertSettingsSchema = z.object({
  enabled: z.boolean().optional(),
  minRisk: z.enum(['LOW', 'MEDIUM', 'HIGH']).optional(),
  email: z.string().email().optional(),
})

// GET /api/settings/alerts - Get alert settings
export async function GET(request: NextRequest) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    let settings = await prisma.alertSettings.findUnique({
      where: { userId: session.userId },
    })

    // Create default settings if none exist
    if (!settings) {
      const user = await prisma.user.findUnique({
        where: { id: session.userId },
        select: { email: true },
      })

      settings = await prisma.alertSettings.create({
        data: {
          userId: session.userId,
          enabled: true,
          minRisk: 'MEDIUM',
          email: user?.email || '',
        },
      })
    }

    return NextResponse.json(settings)
  } catch (error) {
    console.error('Error fetching alert settings:', error)
    return NextResponse.json(
      { error: 'Failed to fetch alert settings' },
      { status: 500 }
    )
  }
}

// POST /api/settings/alerts - Update alert settings
export async function POST(request: NextRequest) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const body = await request.json()
    const updates = alertSettingsSchema.parse(body)

    let settings = await prisma.alertSettings.findUnique({
      where: { userId: session.userId },
    })

    if (!settings) {
      const user = await prisma.user.findUnique({
        where: { id: session.userId },
        select: { email: true },
      })

      settings = await prisma.alertSettings.create({
        data: {
          userId: session.userId,
          enabled: updates.enabled ?? true,
          minRisk: updates.minRisk || 'MEDIUM',
          email: updates.email || user?.email || '',
        },
      })
    } else {
      settings = await prisma.alertSettings.update({
        where: { userId: session.userId },
        data: updates,
      })
    }

    return NextResponse.json(settings)
  } catch (error) {
    console.error('Error updating alert settings:', error)
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.errors[0].message },
        { status: 400 }
      )
    }
    return NextResponse.json(
      { error: 'Failed to update alert settings' },
      { status: 500 }
    )
  }
}

