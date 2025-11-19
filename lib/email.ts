import nodemailer from 'nodemailer'

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
})

export async function sendAlertEmail(
  to: string,
  scanUrl: string,
  riskLevel: string,
  riskScore: number,
  scanId: string
) {
  const riskColor = riskLevel === 'HIGH' ? '#dc2626' :
                    riskLevel === 'MEDIUM' ? '#eab308' : '#22c55e'

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; }
          .content { background: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px; }
          .risk-badge { display: inline-block; padding: 8px 16px; border-radius: 4px; color: white; font-weight: bold; }
          .button { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; text-decoration: none; border-radius: 6px; margin-top: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔒 Security Alert</h1>
          </div>
          <div class="content">
            <p>A security scan has detected potential vulnerabilities:</p>
            <p><strong>URL:</strong> ${scanUrl}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge" style="background: ${riskColor}">${riskLevel}</span></p>
            <p><strong>Risk Score:</strong> ${riskScore}</p>
            <p>Please review the scan results and take appropriate action.</p>
            <a href="${process.env.NEXTAUTH_URL || 'http://localhost:3000'}/scans/${scanId}" class="button">View Scan Details</a>
          </div>
        </div>
      </body>
    </html>
  `

  const text = `
Security Alert

A security scan has detected potential vulnerabilities:

URL: ${scanUrl}
Risk Level: ${riskLevel}
Risk Score: ${riskScore}

Please review the scan results and take appropriate action.
View scan: ${process.env.NEXTAUTH_URL || 'http://localhost:3000'}/scans/${scanId}
  `

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to,
      subject: `Security Alert: ${riskLevel} Risk Detected - ${scanUrl}`,
      text,
      html,
    })
    return true
  } catch (error) {
    console.error('Error sending email:', error)
    return false
  }
}

