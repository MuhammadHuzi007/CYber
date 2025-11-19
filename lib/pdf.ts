import { jsPDF } from 'jspdf'

export interface ScanReportData {
  url: string
  date: string
  riskScore: number
  riskLevel: string
  findings: Array<{
    type: string
    title: string
    severity: string
    passed: boolean
    details?: string
  }>
}

export function generatePDF(data: ScanReportData): jsPDF {
  const doc = new jsPDF()
  
  // Title
  doc.setFontSize(20)
  doc.text('Vulnerability Scan Report', 20, 20)
  
  // Basic Info
  doc.setFontSize(12)
  let yPos = 35
  
  doc.setFont(undefined, 'bold')
  doc.text('Scan Information:', 20, yPos)
  yPos += 8
  
  doc.setFont(undefined, 'normal')
  doc.text(`URL: ${data.url}`, 20, yPos)
  yPos += 7
  doc.text(`Date: ${data.date}`, 20, yPos)
  yPos += 7
  doc.text(`Risk Score: ${data.riskScore}`, 20, yPos)
  yPos += 7
  doc.text(`Risk Level: ${data.riskLevel}`, 20, yPos)
  yPos += 12
  
  // Findings
  doc.setFont(undefined, 'bold')
  doc.text('Findings:', 20, yPos)
  yPos += 8
  
  doc.setFont(undefined, 'normal')
  doc.setFontSize(10)
  
  for (const finding of data.findings) {
    if (yPos > 270) {
      doc.addPage()
      yPos = 20
    }
    
    const status = finding.passed ? '✓ PASS' : '✗ FAIL'
    const color = finding.passed ? [0, 150, 0] : [200, 0, 0]
    
    doc.setTextColor(...color)
    doc.text(`${status} - ${finding.title}`, 20, yPos)
    yPos += 6
    
    doc.setTextColor(0, 0, 0)
    doc.setFontSize(8)
    doc.text(`Type: ${finding.type} | Severity: ${finding.severity}`, 25, yPos)
    yPos += 5
    
    if (finding.details) {
      const details = doc.splitTextToSize(finding.details, 170)
      doc.text(details, 25, yPos)
      yPos += details.length * 5
    }
    
    yPos += 3
    doc.setFontSize(10)
  }
  
  return doc
}

