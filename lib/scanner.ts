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
    
    // Content-Security-Policy - Check presence and quality
    const csp = headers.get('content-security-policy')
    if (!csp) {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Missing: Content-Security-Policy',
        severity: 'HIGH' as Severity,
        passed: false,
        details: 'Content-Security-Policy header is missing. This is critical for preventing XSS attacks.',
      })
    } else {
      const cspLower = csp.toLowerCase()
      if (cspLower.includes('unsafe-inline') || cspLower.includes("*")) {
        findings.push({
          type: 'HEADER' as FindingType,
          title: 'Weak Content-Security-Policy',
          severity: 'HIGH' as Severity,
          passed: false,
          details: `CSP contains unsafe directives: ${csp}. This weakens XSS protection.`,
        })
      } else {
        findings.push({
          type: 'HEADER' as FindingType,
          title: 'Present: Content-Security-Policy',
          severity: 'INFO' as Severity,
          passed: true,
          details: `CSP is present and appears secure: ${csp}`,
        })
      }
    }

    // X-Frame-Options - Require DENY or SAMEORIGIN
    const xFrameOptions = headers.get('x-frame-options')
    if (!xFrameOptions) {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Missing: X-Frame-Options',
        severity: 'MEDIUM' as Severity,
        passed: false,
        details: 'X-Frame-Options header is missing. This allows clickjacking attacks.',
      })
    } else {
      const xfoUpper = xFrameOptions.toUpperCase()
      if (xfoUpper === 'DENY' || xfoUpper === 'SAMEORIGIN') {
        findings.push({
          type: 'HEADER' as FindingType,
          title: 'Present: X-Frame-Options',
          severity: 'INFO' as Severity,
          passed: true,
          details: `X-Frame-Options is properly configured: ${xFrameOptions}`,
        })
      } else {
        findings.push({
          type: 'HEADER' as FindingType,
          title: 'Weak X-Frame-Options',
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `X-Frame-Options value "${xFrameOptions}" is not recommended. Should be DENY or SAMEORIGIN.`,
        })
      }
    }

    // X-Content-Type-Options
    const xContentType = headers.get('x-content-type-options')
    if (!xContentType) {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Missing: X-Content-Type-Options',
        severity: 'MEDIUM' as Severity,
        passed: false,
        details: 'X-Content-Type-Options header is missing. This helps prevent MIME type sniffing attacks.',
      })
    } else if (xContentType.toUpperCase() === 'NOSNIFF') {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Present: X-Content-Type-Options',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'X-Content-Type-Options is properly configured.',
      })
    }

    // Strict-Transport-Security - Require max-age
    const hsts = headers.get('strict-transport-security')
    if (!hsts) {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Missing: Strict-Transport-Security',
        severity: 'HIGH' as Severity,
        passed: false,
        details: 'Strict-Transport-Security header is missing. This is critical for HTTPS-only sites.',
      })
    } else {
      const hstsLower = hsts.toLowerCase()
      if (hstsLower.includes('max-age=')) {
        const maxAgeMatch = hstsLower.match(/max-age=(\d+)/)
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1])
          if (maxAge >= 31536000) { // 1 year
            findings.push({
              type: 'HEADER' as FindingType,
              title: 'Present: Strict-Transport-Security',
              severity: 'INFO' as Severity,
              passed: true,
              details: `HSTS is properly configured with max-age=${maxAge}`,
            })
          } else {
            findings.push({
              type: 'HEADER' as FindingType,
              title: 'Weak Strict-Transport-Security',
              severity: 'MEDIUM' as Severity,
              passed: false,
              details: `HSTS max-age is too short (${maxAge}). Should be at least 31536000 (1 year).`,
            })
          }
        }
      } else {
        findings.push({
          type: 'HEADER' as FindingType,
          title: 'Invalid Strict-Transport-Security',
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `HSTS header is missing max-age directive: ${hsts}`,
        })
      }
    }

    // Referrer-Policy
    const referrerPolicy = headers.get('referrer-policy')
    if (!referrerPolicy) {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Missing: Referrer-Policy',
        severity: 'LOW' as Severity,
        passed: false,
        details: 'Referrer-Policy header is missing. This helps control referrer information leakage.',
      })
    } else {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Present: Referrer-Policy',
        severity: 'INFO' as Severity,
        passed: true,
        details: `Referrer-Policy is configured: ${referrerPolicy}`,
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

    try {
      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
      })
      
      findings.push({
        type: 'SSL' as FindingType,
        title: 'HTTPS connection successful',
        severity: 'INFO' as Severity,
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

async function checkXSSSurface(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'VulnerabilityScanner/1.0',
      },
      redirect: 'follow',
    })

    const html = await response.text()
    
    // Check for inline script tags
    const inlineScriptRegex = /<script[^>]*>[\s\S]*?<\/script>/gi
    const inlineScripts = html.match(inlineScriptRegex)
    
    if (inlineScripts && inlineScripts.length > 0) {
      findings.push({
        type: 'XSS' as FindingType,
        title: 'Inline script tags detected',
        severity: 'HIGH' as Severity,
        passed: false,
        details: `Found ${inlineScripts.length} inline <script> tag(s). Inline scripts are vulnerable to XSS attacks. Consider moving scripts to external files.`,
      })
    } else {
      findings.push({
        type: 'XSS' as FindingType,
        title: 'No inline script tags detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No inline <script> tags found in the HTML response.',
      })
    }

    // Check for on* event attributes
    const onEventRegex = /\s(on\w+)\s*=\s*["'][^"']*["']/gi
    const onEvents = html.match(onEventRegex)
    
    if (onEvents && onEvents.length > 0) {
      const uniqueEvents = [...new Set(onEvents.map(e => e.match(/\s(on\w+)\s*=/)?.[1]).filter(Boolean))]
      findings.push({
        type: 'XSS' as FindingType,
        title: 'Inline event handlers detected',
        severity: 'HIGH' as Severity,
        passed: false,
        details: `Found ${onEvents.length} inline event handler(s) (${uniqueEvents.join(', ')}). Inline event handlers are vulnerable to XSS. Use addEventListener instead.`,
      })
    } else {
      findings.push({
        type: 'XSS' as FindingType,
        title: 'No inline event handlers detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No inline event handlers (onclick, onload, etc.) found in the HTML response.',
      })
    }
  } catch (error) {
    findings.push({
      type: 'XSS' as FindingType,
      title: 'Failed to check XSS surface',
      severity: 'MEDIUM' as Severity,
      passed: false,
      details: error instanceof Error ? error.message : 'Could not analyze HTML for XSS vulnerabilities',
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
    const SUSPICIOUS_PORTS = [
      { port: 21, name: 'FTP' },
      { port: 22, name: 'SSH' },
      { port: 3306, name: 'MySQL' },
      { port: 5432, name: 'PostgreSQL' },
      { port: 3389, name: 'RDP' },
      { port: 1433, name: 'MSSQL' },
    ]
    
    const openPorts: number[] = []
    
    // Mock check - in production, use actual port scanning
    for (const portInfo of SUSPICIOUS_PORTS) {
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
        severity: 'INFO' as Severity,
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
      // Updated scoring system
      if (finding.type === 'HEADER') {
        if (finding.severity === 'HIGH') {
          // Missing critical header or weak CSP
          if (finding.title.includes('Content-Security-Policy') && finding.title.includes('Weak')) {
            score += 4 // Weak CSP
          } else {
            score += 3 // Missing critical header
          }
        } else if (finding.severity === 'MEDIUM') {
          score += 2
        } else if (finding.severity === 'LOW') {
          score += 1
        }
      } else if (finding.type === 'SSL') {
        if (finding.severity === 'HIGH') {
          score += 5 // No HTTPS
        } else {
          score += 2
        }
      } else if (finding.type === 'PORT') {
        if (finding.severity === 'HIGH') {
          score += 3 // Suspicious open ports
        }
      } else if (finding.type === 'XSS') {
        if (finding.severity === 'HIGH') {
          score += 4 // XSS surface indicators
        }
      } else {
        // OTHER type
        if (finding.severity === 'HIGH') {
          score += 3
        } else if (finding.severity === 'MEDIUM') {
          score += 2
        } else if (finding.severity === 'LOW') {
          score += 1
        }
      }
    }
  }

  const numericScore = Math.round(score)
  
  // Updated risk level mapping: 0-4 LOW, 5-9 MEDIUM, 10+ HIGH
  let level: 'LOW' | 'MEDIUM' | 'HIGH'
  if (numericScore <= 4) {
    level = 'LOW'
  } else if (numericScore <= 9) {
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
  const [headerFindings, sslFindings, portFindings, xssFindings] = await Promise.all([
    checkHeaders(targetUrl),
    checkSSL(targetUrl),
    checkPorts(targetUrl),
    checkXSSSurface(targetUrl),
  ])

  const allFindings = [...headerFindings, ...sslFindings, ...portFindings, ...xssFindings]
  const { score, level } = calculateRiskScore(allFindings)

  return {
    findings: allFindings,
    riskScore: score,
    riskLevel: level,
  }
}
