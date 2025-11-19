import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { getSession } from '@/lib/session'
import { z } from 'zod'

const scheduleSchema = z.object({
  url: z.string().url('Invalid URL format'),
  frequency: z.enum(['daily', 'weekly', 'monthly']),
  cron: z.string().optional(),
})

// POST /api/schedules - Create a schedule
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
    const { url, frequency, cron } = scheduleSchema.parse(body)

    // Calculate nextRunAt based on frequency
    const nextRunAt = calculateNextRun(frequency)

    const schedule = await prisma.scanSchedule.create({
      data: {
        orgId: null, // No longer using orgs
        userId: session.userId,
        url,
        frequency,
        cron: cron || null,
        nextRunAt,
      },
    })

    return NextResponse.json(schedule, { status: 201 })
  } catch (error) {
    console.error('Error creating schedule:', error)
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.errors[0].message },
        { status: 400 }
      )
    }
    return NextResponse.json(
      { error: 'Failed to create schedule' },
      { status: 500 }
    )
  }
}

// GET /api/schedules - List schedules for current org
export async function GET(request: NextRequest) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const schedules = await prisma.scanSchedule.findMany({
      where: {
        userId: session.userId,
      },
      orderBy: {
        nextRunAt: 'asc',
      },
    })

    return NextResponse.json({ schedules })
  } catch (error) {
    console.error('Error fetching schedules:', error)
    return NextResponse.json(
      { error: 'Failed to fetch schedules' },
      { status: 500 }
    )
  }
}

function calculateNextRun(frequency: string): Date {
  const now = new Date()
  const next = new Date(now)

  switch (frequency) {
    case 'daily':
      next.setDate(next.getDate() + 1)
      next.setHours(0, 0, 0, 0)
      break
    case 'weekly':
      next.setDate(next.getDate() + 7)
      next.setHours(0, 0, 0, 0)
      break
    case 'monthly':
      next.setMonth(next.getMonth() + 1)
      next.setHours(0, 0, 0, 0)
      break
    default:
      next.setDate(next.getDate() + 1)
  }

  return next
}

