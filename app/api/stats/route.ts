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

    // If no orgId in session, get user's first org
    let orgId = session.orgId
    if (!orgId) {
      const { getUserOrgs } = await import('@/lib/org')
      const orgs = await getUserOrgs(session.userId)
      if (orgs.length === 0) {
        return NextResponse.json(
          { error: 'No organization found' },
          { status: 400 }
        )
      }
      orgId = orgs[0].id
      // Update session with orgId
      const { updateSessionOrg } = await import('@/lib/session')
      await updateSessionOrg(orgId)
    }

    // Get total scans
    const totalScans = await prisma.scan.count({
      where: { orgId },
    })

    // Get scans by risk level
    const byRisk = {
      LOW: await prisma.scan.count({
        where: { orgId, riskLevel: 'LOW' },
      }),
      MEDIUM: await prisma.scan.count({
        where: { orgId, riskLevel: 'MEDIUM' },
      }),
      HIGH: await prisma.scan.count({
        where: { orgId, riskLevel: 'HIGH' },
      }),
    }

    // Get recent scans (last 5)
    const recentScans = await prisma.scan.findMany({
      where: { orgId },
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

