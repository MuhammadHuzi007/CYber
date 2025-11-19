import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { scanUrl } from '@/lib/scanner'

// This endpoint should be protected with a secret token in production
const CRON_SECRET = process.env.CRON_SECRET || 'change-me-in-production'

export async function GET(request: NextRequest) {
  try {
    // Verify cron secret
    const authHeader = request.headers.get('authorization')
    if (authHeader !== `Bearer ${CRON_SECRET}`) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const now = new Date()

    // Find schedules that are due
    const dueSchedules = await prisma.scanSchedule.findMany({
      where: {
        active: true,
        nextRunAt: {
          lte: now,
        },
      },
    })

    const results = []

    for (const schedule of dueSchedules) {
      try {
        // Create scan
        const scan = await prisma.scan.create({
          data: {
            url: schedule.url,
            userId: schedule.userId,
            orgId: null,
            scheduleId: schedule.id,
            riskScore: 0,
            riskLevel: 'LOW',
            status: 'PENDING',
          },
        })

        // Run scan
        const result = await scanUrl(schedule.url)

        // Update scan with results
        await prisma.scan.update({
          where: { id: scan.id },
          data: {
            riskScore: result.riskScore,
            riskLevel: result.riskLevel,
            status: 'COMPLETED',
            completedAt: new Date(),
          },
        })

        // Create findings
        await prisma.finding.createMany({
          data: result.findings.map((finding) => ({
            scanId: scan.id,
            type: finding.type,
            title: finding.title,
            severity: finding.severity,
            passed: finding.passed,
            details: finding.details || null,
          })),
        })

        // Update schedule
        const nextRunAt = calculateNextRun(schedule.frequency)
        await prisma.scanSchedule.update({
          where: { id: schedule.id },
          data: {
            lastRunAt: new Date(),
            nextRunAt,
          },
        })

        // Check for alerts
        await checkAndSendAlerts(schedule.userId, scan.id, result.riskLevel)

        results.push({
          scheduleId: schedule.id,
          scanId: scan.id,
          status: 'success',
        })
      } catch (error) {
        console.error(`Error running schedule ${schedule.id}:`, error)
        
        // Mark scan as failed
        await prisma.scan.updateMany({
          where: {
            scheduleId: schedule.id,
            status: 'PENDING',
          },
          data: {
            status: 'FAILED',
            completedAt: new Date(),
          },
        })

        results.push({
          scheduleId: schedule.id,
          status: 'error',
          error: error instanceof Error ? error.message : 'Unknown error',
        })
      }
    }

    return NextResponse.json({
      processed: dueSchedules.length,
      results,
    })
  } catch (error) {
    console.error('Error running scheduled scans:', error)
    return NextResponse.json(
      { error: 'Failed to run scheduled scans' },
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

async function checkAndSendAlerts(orgId: string, scanId: string, riskLevel: string) {
  try {
    // Get scan details
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        user: {
          include: {
            alertSettings: true,
          },
        },
      },
    })

    if (!scan || !scan.user) return

    const settings = scan.user.alertSettings
    if (!settings || !settings.enabled) return

    // Check if risk level meets threshold
    const riskLevels = ['LOW', 'MEDIUM', 'HIGH']
    const scanRiskIndex = riskLevels.indexOf(riskLevel)
    const minRiskIndex = riskLevels.indexOf(settings.minRisk)

    if (scanRiskIndex >= minRiskIndex) {
      // Import email function
      const { sendAlertEmail } = await import('@/lib/email')
      await sendAlertEmail(
        settings.email,
        scan.url,
        riskLevel,
        scan.riskScore,
        scanId
      )
    }
  } catch (error) {
    console.error('Error checking/sending alerts:', error)
  }
}

