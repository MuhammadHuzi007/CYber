import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { scanUrl } from '@/lib/scanner'
import { z } from 'zod'

const scanSchema = z.object({
  url: z.string().url('Invalid URL format'),
  userId: z.string().optional(),
})

// POST /api/scans - Create and run a new scan
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { url, userId } = scanSchema.parse(body)

    // Create scan with PENDING status
    const scan = await prisma.scan.create({
      data: {
        url,
        userId: userId || null,
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

// GET /api/scans - Get all scans (optionally filtered by userId)
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const userId = searchParams.get('userId')
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '10')
    const skip = (page - 1) * limit

    const where = userId ? { userId } : {}

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

