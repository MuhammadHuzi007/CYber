import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { generatePDF } from '@/lib/pdf'

// GET /api/scans/[id]/report - Generate and download PDF report
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

    const pdf = generatePDF({
      url: scan.url,
      date: scan.startedAt.toISOString(),
      riskScore: scan.riskScore,
      riskLevel: scan.riskLevel,
      findings: scan.findings.map((f) => ({
        type: f.type,
        title: f.title,
        severity: f.severity,
        passed: f.passed,
        details: f.details || undefined,
      })),
    })

    // Generate PDF as buffer (works in Node.js)
    const pdfBuffer = Buffer.from(pdf.output('arraybuffer'))

    return new NextResponse(pdfBuffer, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="scan-report-${scan.id}.pdf"`,
      },
    })
  } catch (error) {
    console.error('Error generating report:', error)
    return NextResponse.json(
      { error: 'Failed to generate report' },
      { status: 500 }
    )
  }
}

