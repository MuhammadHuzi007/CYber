import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/session'
import { prisma } from '@/lib/prisma'

export async function GET(request: NextRequest) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const userId = session.userId

    // Get total scans
    const totalScans = await prisma.scan.count({
      where: { userId },
    })

    // Get scans by risk level
    const byRisk = {
      LOW: await prisma.scan.count({
        where: { userId, riskLevel: 'LOW' },
      }),
      MEDIUM: await prisma.scan.count({
        where: { userId, riskLevel: 'MEDIUM' },
      }),
      HIGH: await prisma.scan.count({
        where: { userId, riskLevel: 'HIGH' },
      }),
    }

    // Get recent scans (last 5)
    const recentScans = await prisma.scan.findMany({
      where: { userId },
      orderBy: { startedAt: 'desc' },
      take: 5,
      select: {
        id: true,
        url: true,
        riskScore: true,
        riskLevel: true,
        status: true,
        startedAt: true,
      },
    })

    return NextResponse.json({
      totalScans,
      byRisk,
      recentScans,
    })
  } catch (error) {
    console.error('Error fetching stats:', error)
    return NextResponse.json(
      { error: 'Failed to fetch stats' },
      { status: 500 }
    )
  }
}

