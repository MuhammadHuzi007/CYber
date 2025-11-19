import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Vulnerability Scanner Dashboard | Enterprise Security Analysis',
  description: 'Comprehensive security scanning for vulnerabilities, headers, SSL, and open ports. Professional vulnerability assessment tool.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  )
}

