import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/session'
import { getUserOrgs } from '@/lib/org'

export async function GET(request: NextRequest) {
  try {
    const session = await getSession()
    
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const orgs = await getUserOrgs(session.userId)

    return NextResponse.json({ orgs })
  } catch (error) {
    console.error('Error fetching orgs:', error)
    return NextResponse.json(
      { error: 'Failed to fetch organizations' },
      { status: 500 }
    )
  }
}

