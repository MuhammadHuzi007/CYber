import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { getSession } from '@/lib/session'
import { z } from 'zod'

const updateSchema = z.object({
  url: z.string().url('Invalid URL format').optional(),
  frequency: z.enum(['daily', 'weekly', 'monthly']).optional(),
  active: z.boolean().optional(),
})

// PATCH /api/schedules/[id] - Update schedule
export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const body = await request.json()
    const updates = updateSchema.parse(body)

    // Verify schedule belongs to user
    const schedule = await prisma.scanSchedule.findUnique({
      where: { id: params.id },
    })

    if (!schedule || schedule.userId !== session.userId) {
      return NextResponse.json(
        { error: 'Schedule not found' },
        { status: 404 }
      )
    }

    // Calculate nextRunAt if frequency changed
    const updateData: any = { ...updates }
    if (updates.frequency) {
      const nextRunAt = calculateNextRun(updates.frequency)
      updateData.nextRunAt = nextRunAt
    }

    const updated = await prisma.scanSchedule.update({
      where: { id: params.id },
      data: updateData,
    })

    return NextResponse.json(updated)
  } catch (error) {
    console.error('Error updating schedule:', error)
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.errors[0].message },
        { status: 400 }
      )
    }
    return NextResponse.json(
      { error: 'Failed to update schedule' },
      { status: 500 }
    )
  }
}

// DELETE /api/schedules/[id] - Delete schedule
export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // Verify schedule belongs to user
    const schedule = await prisma.scanSchedule.findUnique({
      where: { id: params.id },
    })

    if (!schedule || schedule.userId !== session.userId) {
      return NextResponse.json(
        { error: 'Schedule not found' },
        { status: 404 }
      )
    }

    await prisma.scanSchedule.delete({
      where: { id: params.id },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Error deleting schedule:', error)
    return NextResponse.json(
      { error: 'Failed to delete schedule' },
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
