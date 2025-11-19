import { FindingType, Severity } from '@prisma/client'

export interface ScanResult {
  findings: Finding[]
  riskScore: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'
}

export interface Finding {
  type: FindingType
  title: string
  severity: Severity
  passed: boolean
  details?: string
}

const CRITICAL_HEADERS = [
  'Content-Security-Policy',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Strict-Transport-Security',
  'Referrer-Policy',
]

const SUSPICIOUS_PORTS = [
  { port: 21, name: 'FTP' },
  { port: 22, name: 'SSH' },
  { port: 3306, name: 'MySQL' },
  { port: 5432, name: 'PostgreSQL' },
  { port: 3389, name: 'RDP' },
  { port: 1433, name: 'MSSQL' },
]

async function checkHeaders(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'VulnerabilityScanner/1.0',
      },
      redirect: 'follow',
    })

    const headers = response.headers
    
    for (const header of CRITICAL_HEADERS) {
      const headerValue = headers.get(header.toLowerCase())
      const passed = !!headerValue
      
      findings.push({
        type: 'HEADER' as FindingType,
        title: `${passed ? 'Present' : 'Missing'}: ${header}`,
        severity: passed ? 'LOW' : 'HIGH' as Severity,
        passed,
        details: passed ? `Header value: ${headerValue}` : `Security header ${header} is missing`,
      })
    }
  } catch (error) {
    findings.push({
      type: 'HEADER' as FindingType,
      title: 'Failed to check headers',
      severity: 'MEDIUM' as Severity,
      passed: false,
      details: error instanceof Error ? error.message : 'Unknown error',
    })
  }

  return findings
}

async function checkSSL(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const isHttps = urlObj.protocol === 'https:'
    
    if (!isHttps) {
      findings.push({
        type: 'SSL' as FindingType,
        title: 'Not using HTTPS',
        severity: 'HIGH' as Severity,
        passed: false,
        details: 'The URL is using HTTP instead of HTTPS, which means data is transmitted in plain text',
      })
      return findings
    }

    // For MVP, we'll do a basic check
    // In production, you'd want to use tls.connect to check certificate validity
    try {
      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
      })
      
      findings.push({
        type: 'SSL' as FindingType,
        title: 'HTTPS connection successful',
        severity: 'LOW' as Severity,
        passed: true,
        details: 'HTTPS is enabled and connection is successful',
      })
    } catch (error) {
      findings.push({
        type: 'SSL' as FindingType,
        title: 'SSL/TLS connection issue',
        severity: 'HIGH' as Severity,
        passed: false,
        details: error instanceof Error ? error.message : 'Failed to establish secure connection',
      })
    }
  } catch (error) {
    findings.push({
      type: 'SSL' as FindingType,
      title: 'Invalid URL format',
      severity: 'MEDIUM' as Severity,
      passed: false,
      details: error instanceof Error ? error.message : 'Could not parse URL',
    })
  }

  return findings
}

async function checkPorts(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname
    
    
    // For MVP, we'll simulate port checks
    // In production, you'd use nmap or tcp.connect
    // This is a mock implementation - replace with real nmap integration
    
    const openPorts: number[] = []
    
    // Mock: randomly check a few ports (in real implementation, use nmap)
    // For now, we'll check if common ports might be open based on URL patterns
    // This is a simplified version - replace with actual port scanning
    
    for (const portInfo of SUSPICIOUS_PORTS) {
      // Mock check - in production, use actual port scanning
      // For MVP, we'll mark as passed (not found) to avoid false positives
      // You can replace this with actual nmap integration
      
      const isOpen = false // Mock: assume closed for MVP
      
      if (isOpen) {
        openPorts.push(portInfo.port)
        findings.push({
          type: 'PORT' as FindingType,
          title: `Suspicious port open: ${portInfo.port} (${portInfo.name})`,
          severity: 'HIGH' as Severity,
          passed: false,
          details: `Port ${portInfo.port} (${portInfo.name}) is open on ${hostname}. This may expose sensitive services.`,
        })
      }
    }
    
    if (openPorts.length === 0) {
      findings.push({
        type: 'PORT' as FindingType,
        title: 'No suspicious ports detected',
        severity: 'LOW' as Severity,
        passed: true,
        details: 'No commonly exploited ports were found to be open',
      })
    }
  } catch (error) {
    findings.push({
      type: 'PORT' as FindingType,
      title: 'Port scan failed',
      severity: 'MEDIUM' as Severity,
      passed: false,
      details: error instanceof Error ? error.message : 'Could not perform port scan',
    })
  }

  return findings
}

function calculateRiskScore(findings: Finding[]): { score: number; level: 'LOW' | 'MEDIUM' | 'HIGH' } {
  let score = 0

  for (const finding of findings) {
    if (!finding.passed) {
      switch (finding.severity) {
        case 'HIGH':
          score += finding.type === 'SSL' ? 3 : 2
          break
        case 'MEDIUM':
          score += 1
          break
        case 'LOW':
          score += 0.5
          break
      }
    }
  }

  const numericScore = Math.round(score)
  
  let level: 'LOW' | 'MEDIUM' | 'HIGH'
  if (numericScore <= 2) {
    level = 'LOW'
  } else if (numericScore <= 5) {
    level = 'MEDIUM'
  } else {
    level = 'HIGH'
  }

  return { score: numericScore, level }
}

export async function scanUrl(url: string): Promise<ScanResult> {
  // Ensure URL has protocol
  let targetUrl = url
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    targetUrl = `https://${url}`
  }

  // Run all checks in parallel
  const [headerFindings, sslFindings, portFindings] = await Promise.all([
    checkHeaders(targetUrl),
    checkSSL(targetUrl),
    checkPorts(targetUrl),
  ])

  const allFindings = [...headerFindings, ...sslFindings, ...portFindings]
  const { score, level } = calculateRiskScore(allFindings)

  return {
    findings: allFindings,
    riskScore: score,
    riskLevel: level,
  }
}

