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

async function checkDirectoryListing(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const commonPaths = ['/', '/uploads/', '/images/', '/backup/', '/files/', '/public/']
  
  for (const path of commonPaths) {
    try {
      const testUrl = new URL(path, url).toString()
      const response = await fetch(testUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
        redirect: 'follow',
      })
      
      const html = await response.text()
      const lowerHtml = html.toLowerCase()
      
      if (lowerHtml.includes('index of') || 
          lowerHtml.includes('directory listing') ||
          lowerHtml.includes('<title>index of') ||
          (lowerHtml.includes('<pre>') && lowerHtml.includes('parent directory'))) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: `Directory listing enabled on ${path}`,
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `Directory listing appears to be enabled on ${path}. This can expose sensitive files and directory structure.`,
        })
      }
    } catch (error) {
      // Ignore errors for individual paths
    }
  }
  
  if (findings.length === 0) {
    findings.push({
      type: 'OTHER' as FindingType,
      title: 'No directory listing detected',
      severity: 'INFO' as Severity,
      passed: true,
      details: 'No directory listing was detected on common paths.',
    })
  }
  
  return findings
}

async function checkHTTPMethods(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  const unsafeMethods = ['PUT', 'DELETE', 'TRACE', 'PATCH']
  
  for (const method of unsafeMethods) {
    try {
      const response = await fetch(url, {
        method: method as any,
        headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
        redirect: 'follow',
      })
      
      // If method is allowed (not 405 Method Not Allowed)
      if (response.status !== 405 && response.status < 500) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: `Potentially unsafe HTTP method enabled: ${method}`,
          severity: response.status < 400 ? 'HIGH' : 'MEDIUM' as Severity,
          passed: false,
          details: `HTTP ${method} method is enabled and returned status ${response.status}. This method should be disabled if not needed.`,
        })
      }
    } catch (error) {
      // Ignore errors
    }
  }
  
  if (findings.length === 0) {
    findings.push({
      type: 'OTHER' as FindingType,
      title: 'Unsafe HTTP methods appear disabled',
      severity: 'INFO' as Severity,
      passed: true,
      details: 'PUT, DELETE, TRACE, and PATCH methods appear to be disabled or not allowed.',
    })
  }
  
  return findings
}

async function checkMixedContent(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    if (urlObj.protocol !== 'https:') {
      return findings // Only check for mixed content on HTTPS pages
    }
    
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
      redirect: 'follow',
    })
    
    const html = await response.text()
    
    // Check for HTTP resources in HTTPS page
    const httpResourceRegex = /(src|href|action)=["'](http:\/\/[^"']+)["']/gi
    const matches = html.match(httpResourceRegex)
    
    if (matches && matches.length > 0) {
      const uniqueResources = [...new Set(matches.map(m => m.match(/http:\/\/[^"']+/)?.[0]).filter(Boolean))]
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'Mixed content detected (insecure HTTP resources on HTTPS page)',
        severity: 'MEDIUM' as Severity,
        passed: false,
        details: `Found ${uniqueResources.length} HTTP resource(s) loaded on HTTPS page: ${uniqueResources.slice(0, 3).join(', ')}${uniqueResources.length > 3 ? '...' : ''}. This can be exploited by attackers.`,
      })
    } else {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No mixed content detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No HTTP resources found on HTTPS page.',
      })
    }
  } catch (error) {
    // Ignore errors
  }
  
  return findings
}

async function checkSecurityTxt(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`
    
    // Check for security.txt
    try {
      const securityTxtUrl = `${baseUrl}/.well-known/security.txt`
      const response = await fetch(securityTxtUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
        redirect: 'follow',
      })
      
      if (response.ok) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'security.txt found',
          severity: 'INFO' as Severity,
          passed: true,
          details: 'security.txt file is present at /.well-known/security.txt',
        })
      } else {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'security.txt not found',
          severity: 'INFO' as Severity,
          passed: false,
          details: 'security.txt file is missing. Consider adding one at /.well-known/security.txt for security researchers.',
        })
      }
    } catch (error) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'security.txt not found',
        severity: 'INFO' as Severity,
        passed: false,
        details: 'security.txt file is missing. Consider adding one at /.well-known/security.txt for security researchers.',
      })
    }
    
    // Check for robots.txt (informational)
    try {
      const robotsTxtUrl = `${baseUrl}/robots.txt`
      const response = await fetch(robotsTxtUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
        redirect: 'follow',
      })
      
      if (response.ok) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'robots.txt found',
          severity: 'INFO' as Severity,
          passed: true,
          details: 'robots.txt file is present',
        })
      }
    } catch (error) {
      // Ignore robots.txt errors
    }
  } catch (error) {
    // Ignore errors
  }
  
  return findings
}

async function checkSQLiXSSProbe(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const params = urlObj.searchParams
    
    if (params.toString().length === 0) {
      // No query parameters, skip probing
      return findings
    }
    
    // XSS payloads
    const xssPayloads = [
      '<script>alert(1)</script>',
      '\'"><img src=x onerror=alert(1)>',
      'javascript:alert(1)',
    ]
    
    // SQLi payloads
    const sqliPayloads = [
      "1' OR '1'='1",
      "1'--",
      "' UNION SELECT NULL--",
    ]
    
    // Test XSS
    for (const [key, value] of params.entries()) {
      for (const payload of xssPayloads) {
        try {
          const testUrl = new URL(url)
          testUrl.searchParams.set(key, payload)
          
          const response = await fetch(testUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
            redirect: 'follow',
          })
          
          const html = await response.text()
          
          // Check if payload is reflected unescaped
          if (html.includes(payload) || html.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'))) {
            findings.push({
              type: 'XSS' as FindingType,
              title: `Possible reflected XSS surface on parameter: ${key}`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `The parameter "${key}" appears to reflect user input without proper encoding. This may indicate a reflected XSS vulnerability.`,
            })
            break // Only report once per parameter
          }
        } catch (error) {
          // Ignore errors
        }
      }
    }
    
    // Test SQLi
    for (const [key, value] of params.entries()) {
      for (const payload of sqliPayloads) {
        try {
          const testUrl = new URL(url)
          testUrl.searchParams.set(key, payload)
          
          const response = await fetch(testUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
            redirect: 'follow',
          })
          
          const html = await response.text().toLowerCase()
          
          // Check for SQL error patterns
          const sqlErrorPatterns = [
            'sql syntax',
            'mysql error',
            'postgresql error',
            'ora-',
            'sqlite error',
            'warning: mysql',
            'unclosed quotation mark',
            'quoted string not properly terminated',
          ]
          
          for (const pattern of sqlErrorPatterns) {
            if (html.includes(pattern)) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `Potential SQL error exposure detected on parameter: ${key}`,
                severity: 'HIGH' as Severity,
                passed: false,
                details: `SQL error message detected in response for parameter "${key}". This may indicate a SQL injection vulnerability.`,
              })
              break
            }
          }
        } catch (error) {
          // Ignore errors
        }
      }
    }
  } catch (error) {
    // Ignore errors
  }
  
  return findings
}

async function checkTechFingerprinting(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
      redirect: 'follow',
    })
    
    const headers = response.headers
    
    // Check Server header
    const server = headers.get('server')
    if (server) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: `Server header exposed: ${server}`,
        severity: 'INFO' as Severity,
        passed: false,
        details: `Server header reveals technology stack: ${server}. Consider hiding this information.`,
      })
    }
    
    // Check X-Powered-By header
    const poweredBy = headers.get('x-powered-by')
    if (poweredBy) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: `X-Powered-By header exposed: ${poweredBy}`,
        severity: 'INFO' as Severity,
        passed: false,
        details: `X-Powered-By header reveals technology: ${poweredBy}. Consider removing this header.`,
      })
    }
    
    // Check for other technology indicators
    const techIndicators = [
      { header: 'x-aspnet-version', name: 'ASP.NET' },
      { header: 'x-aspnetmvc-version', name: 'ASP.NET MVC' },
      { header: 'x-runtime', name: 'Runtime version' },
    ]
    
    for (const indicator of techIndicators) {
      const value = headers.get(indicator.header)
      if (value) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: `${indicator.name} exposed: ${value}`,
          severity: 'INFO' as Severity,
          passed: false,
          details: `Technology information exposed via ${indicator.header} header.`,
        })
      }
    }
  } catch (error) {
    // Ignore errors
  }
  
  return findings
}

function calculateRiskScore(findings: Finding[]): { score: number; level: 'LOW' | 'MEDIUM' | 'HIGH' } {
  let score = 0

  for (const finding of findings) {
    if (!finding.passed) {
      // Updated scoring system with new checks
      if (finding.type === 'HEADER') {
        if (finding.severity === 'HIGH') {
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
          // Clear XSS reflection
          if (finding.title.includes('reflected XSS')) {
            score += 6
          } else {
            score += 4 // XSS surface indicators
          }
        }
      } else {
        // OTHER type - includes new checks
        if (finding.title.includes('Directory listing')) {
          score += 3
        } else if (finding.title.includes('HTTP method enabled')) {
          score += 4 // Unsafe methods (PUT/DELETE)
        } else if (finding.title.includes('Mixed content')) {
          score += 3
        } else if (finding.title.includes('SQL error')) {
          score += 5 // SQL errors exposure
        } else if (finding.severity === 'HIGH') {
          score += 3
        } else if (finding.severity === 'MEDIUM') {
          score += 2
        } else if (finding.severity === 'LOW') {
          score += 1
        } else if (finding.severity === 'INFO' && (
          finding.title.includes('security.txt') ||
          finding.title.includes('Server header') ||
          finding.title.includes('X-Powered-By')
        )) {
          score += 1 // Tech fingerprinting / missing security.txt
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
  const [
    headerFindings,
    sslFindings,
    portFindings,
    xssFindings,
    directoryFindings,
    httpMethodFindings,
    mixedContentFindings,
    securityTxtFindings,
    sqliXssProbeFindings,
    techFingerprintFindings,
  ] = await Promise.all([
    checkHeaders(targetUrl),
    checkSSL(targetUrl),
    checkPorts(targetUrl),
    checkXSSSurface(targetUrl),
    checkDirectoryListing(targetUrl),
    checkHTTPMethods(targetUrl),
    checkMixedContent(targetUrl),
    checkSecurityTxt(targetUrl),
    checkSQLiXSSProbe(targetUrl),
    checkTechFingerprinting(targetUrl),
  ])

  const allFindings = [
    ...headerFindings,
    ...sslFindings,
    ...portFindings,
    ...xssFindings,
    ...directoryFindings,
    ...httpMethodFindings,
    ...mixedContentFindings,
    ...securityTxtFindings,
    ...sqliXssProbeFindings,
    ...techFingerprintFindings,
  ]
  const { score, level } = calculateRiskScore(allFindings)

  return {
    findings: allFindings,
    riskScore: score,
    riskLevel: level,
  }
}
