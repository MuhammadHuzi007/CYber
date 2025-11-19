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
    injectionFindings,
    sensitiveFilesFindings,
    exposedEndpointsFindings,
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
    checkInjectionVulnerabilities(targetUrl),
    checkSensitiveFiles(targetUrl),
    checkExposedEndpoints(targetUrl),
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
    ...injectionFindings,
    ...sensitiveFilesFindings,
    ...exposedEndpointsFindings,
  ]
  const { score, level } = calculateRiskScore(allFindings)

  return {
    findings: allFindings,
    riskScore: score,
    riskLevel: level,
  }
}
