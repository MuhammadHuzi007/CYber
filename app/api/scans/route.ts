import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { scanUrl } from '@/lib/scanner'
import { getSession } from '@/lib/session'
import { z } from 'zod'

const scanSchema = z.object({
  url: z.string().url('Invalid URL format'),
  scheduleId: z.string().optional(),
})

async function checkAndSendAlerts(userId: string, scanId: string, riskLevel: string) {
  try {
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

    const riskLevels = ['LOW', 'MEDIUM', 'HIGH']
    const scanRiskIndex = riskLevels.indexOf(riskLevel)
    const minRiskIndex = riskLevels.indexOf(settings.minRisk)

    if (scanRiskIndex >= minRiskIndex) {
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

// POST /api/scans - Create and run a new scan
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
    const { url, scheduleId } = scanSchema.parse(body)

    // Create scan with PENDING status
    const scan = await prisma.scan.create({
      data: {
        url,
        userId: session.userId,
        orgId: null,
        scheduleId: scheduleId || null,
        riskScore: 0,
        riskLevel: 'LOW',
        status: 'PENDING',
      },
    })

    // Run scan in background (for MVP, we'll do it synchronously)
    try {
      const result = await scanUrl(url)

      // Update scan with results
      const updatedScan = await prisma.scan.update({
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

      // Fetch complete scan with findings
      const completeScan = await prisma.scan.findUnique({
        where: { id: scan.id },
        include: {
          findings: true,
        },
      })

      // Check and send alerts
      await checkAndSendAlerts(session.userId, scan.id, result.riskLevel)

      return NextResponse.json(completeScan, { status: 201 })
    } catch (error) {
      // Mark scan as failed
      await prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: 'FAILED',
          completedAt: new Date(),
        },
      })

      throw error
    }
  } catch (error) {
    console.error('Scan error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to create scan' },
      { status: 400 }
    )
  }
}

// GET /api/scans - Get all scans with filters
export async function GET(request: NextRequest) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const searchParams = request.nextUrl.searchParams
    const riskLevel = searchParams.get('riskLevel') as 'LOW' | 'MEDIUM' | 'HIGH' | null
    const q = searchParams.get('q') // URL search
    const from = searchParams.get('from') // Date from (ISO string)
    const to = searchParams.get('to') // Date to (ISO string)
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '10')
    const skip = (page - 1) * limit

    // Build where clause - filter by userId instead of orgId
    const where: any = {
      userId: session.userId,
    }

    if (riskLevel && ['LOW', 'MEDIUM', 'HIGH'].includes(riskLevel)) {
      where.riskLevel = riskLevel
    }

    if (q) {
      where.url = {
        contains: q,
        mode: 'insensitive',
      }
    }

    if (from || to) {
      where.startedAt = {}
      if (from) {
        where.startedAt.gte = new Date(from)
      }
      if (to) {
        where.startedAt.lte = new Date(to)
      }
    }

    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where,
        orderBy: { startedAt: 'desc' },
        skip,
        take: limit,
        include: {
          findings: {
            take: 1, // Just to show if there are findings
          },
        },
      }),
      prisma.scan.count({ where }),
    ])

    return NextResponse.json({
      scans,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    })
  } catch (error) {
    console.error('Error fetching scans:', error)
    return NextResponse.json(
      { error: 'Failed to fetch scans' },
      { status: 500 }
    )
  }
}
