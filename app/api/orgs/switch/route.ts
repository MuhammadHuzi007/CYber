import { NextRequest, NextResponse } from 'next/server'
import { getSession, updateSessionOrg } from '@/lib/session'
import { getOrgMember } from '@/lib/org'

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
    const { orgId } = body

    if (!orgId) {
      return NextResponse.json(
        { error: 'orgId is required' },
        { status: 400 }
      )
    }

    // Verify user is member of org
    const member = await getOrgMember(session.userId, orgId)
    if (!member) {
      return NextResponse.json(
        { error: 'Not a member of this organization' },
        { status: 403 }
      )
    }

    // Update session with new orgId
    await updateSessionOrg(orgId)

    return NextResponse.json({ success: true, orgId })
  } catch (error) {
    console.error('Error switching org:', error)
    return NextResponse.json(
      { error: 'Failed to switch organization' },
      { status: 500 }
    )
  }
}

