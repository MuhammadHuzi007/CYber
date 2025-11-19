import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

// GET /api/scans/[id] - Get a single scan with findings
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: params.id },
      include: {
        findings: {
          orderBy: [
            { severity: 'desc' },
            { passed: 'asc' },
          ],
        },
      },
    })

    if (!scan) {
      return NextResponse.json(
        { error: 'Scan not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(scan)
  } catch (error) {
    console.error('Error fetching scan:', error)
    return NextResponse.json(
      { error: 'Failed to fetch scan' },
      { status: 500 }
    )
  }
}

