import { type NextRequest, NextResponse } from "next/server"
import { rateLimiter } from "@/lib/rate-limiter"
import { validateUrl, sanitizeUrl, getClientIdentifier, logSecurityEvent } from "@/lib/security-utils"

interface PhishingFeatures {
  urlLength: number
  domainLength: number
  hasHttps: boolean
  hasSubdomains: number
  hasSpecialChars: number
  hasSuspiciousWords: boolean
  domainAge: number
  hasRedirect: boolean
  ipAddress: boolean
}

interface AnalysisResult {
  url: string
  isPhishing: boolean
  confidence: number
  riskFactors: string[]
  analysis: {
    domainAge: string
    sslStatus: string
    reputation: string
    suspiciousPatterns: string[]
  }
  screenshot?: string
}

// Suspicious keywords commonly found in phishing URLs
const SUSPICIOUS_KEYWORDS = [
  "secure",
  "account",
  "update",
  "verify",
  "login",
  "signin",
  "banking",
  "paypal",
  "amazon",
  "microsoft",
  "google",
  "apple",
  "facebook",
  "suspended",
  "limited",
  "confirm",
  "urgent",
  "immediate",
]

// Legitimate domain patterns
const LEGITIMATE_DOMAINS = [
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "paypal.com",
  "facebook.com",
  "twitter.com",
  "linkedin.com",
  "github.com",
  "stackoverflow.com",
]

function extractFeatures(url: string): PhishingFeatures {
  try {
    const urlObj = new URL(url)
    const domain = urlObj.hostname
    const path = urlObj.pathname + urlObj.search

    return {
      urlLength: url.length,
      domainLength: domain.length,
      hasHttps: urlObj.protocol === "https:",
      hasSubdomains: domain.split(".").length - 2,
      hasSpecialChars: (url.match(/[-_@]/g) || []).length,
      hasSuspiciousWords: SUSPICIOUS_KEYWORDS.some((keyword) => url.toLowerCase().includes(keyword)),
      domainAge: Math.random() * 365 * 5, // Mock domain age in days
      hasRedirect: path.includes("redirect") || path.includes("r="),
      ipAddress: /^\d+\.\d+\.\d+\.\d+/.test(domain),
    }
  } catch {
    // Invalid URL format
    return {
      urlLength: url.length,
      domainLength: 0,
      hasHttps: false,
      hasSubdomains: 0,
      hasSpecialChars: (url.match(/[-_@]/g) || []).length,
      hasSuspiciousWords: true,
      domainAge: 0,
      hasRedirect: false,
      ipAddress: false,
    }
  }
}

function calculatePhishingScore(features: PhishingFeatures, url: string): number {
  let score = 0

  // URL length analysis
  if (features.urlLength > 100) score += 0.3
  else if (features.urlLength > 50) score += 0.1

  // Domain length analysis
  if (features.domainLength > 30) score += 0.2

  // HTTPS check
  if (!features.hasHttps) score += 0.4

  // Subdomain analysis
  if (features.hasSubdomains > 3) score += 0.3
  else if (features.hasSubdomains > 1) score += 0.1

  // Special characters
  if (features.hasSpecialChars > 5) score += 0.2

  // Suspicious keywords
  if (features.hasSuspiciousWords) score += 0.3

  // Domain age (mock analysis)
  if (features.domainAge < 30) score += 0.4
  else if (features.domainAge < 90) score += 0.2

  // Redirect patterns
  if (features.hasRedirect) score += 0.3

  // IP address instead of domain
  if (features.ipAddress) score += 0.5

  // Check against known legitimate domains
  try {
    const domain = new URL(url).hostname
    if (LEGITIMATE_DOMAINS.some((legit) => domain.includes(legit))) {
      score = Math.max(0, score - 0.6)
    }
  } catch {
    score += 0.2
  }

  return Math.min(1, score)
}

function generateRiskFactors(features: PhishingFeatures, url: string): string[] {
  const factors: string[] = []

  if (features.urlLength > 100) factors.push("Unusually long URL")
  if (!features.hasHttps) factors.push("No HTTPS encryption")
  if (features.hasSubdomains > 2) factors.push("Multiple subdomains detected")
  if (features.hasSuspiciousWords) factors.push("Contains suspicious keywords")
  if (features.domainAge < 30) factors.push("Recently registered domain")
  if (features.hasRedirect) factors.push("Contains redirect patterns")
  if (features.ipAddress) factors.push("Uses IP address instead of domain name")
  if (features.hasSpecialChars > 5) factors.push("Excessive special characters")

  return factors
}

function generateSuspiciousPatterns(features: PhishingFeatures, url: string): string[] {
  const patterns: string[] = []

  if (features.hasSuspiciousWords) patterns.push("Phishing keywords detected")
  if (features.hasRedirect) patterns.push("URL redirection found")
  if (features.ipAddress) patterns.push("Direct IP access")

  // Check for typosquatting patterns
  try {
    const domain = new URL(url).hostname
    const suspiciousChars = domain.match(/[0-9]/g)
    if (suspiciousChars && suspiciousChars.length > 2) {
      patterns.push("Potential typosquatting")
    }
  } catch {
    patterns.push("Invalid URL structure")
  }

  return patterns
}

async function generateMockScreenshot(url: string): Promise<string> {
  // In a real implementation, this would use a service like Puppeteer or Playwright
  // For now, we'll generate a placeholder image URL based on the domain
  try {
    const domain = new URL(url).hostname
    const isPhishing = Math.random() > 0.5 // Mock determination

    // Generate a placeholder screenshot with domain info
    const screenshotUrl = `/placeholder.svg?height=400&width=800&query=${encodeURIComponent(
      `Website screenshot for ${domain} - ${isPhishing ? "Suspicious" : "Legitimate"} site preview`,
    )}`

    return screenshotUrl
  } catch {
    return `/placeholder.svg?height=400&width=800&query=${encodeURIComponent("Invalid URL - No screenshot available")}`
  }
}

export async function POST(request: NextRequest) {
  const clientId = getClientIdentifier(request)

  try {
    if (!rateLimiter.isAllowed(clientId)) {
      logSecurityEvent("RATE_LIMIT_EXCEEDED", { clientId }, request)
      return NextResponse.json(
        {
          error: "Too many requests. Please try again later.",
          retryAfter: Math.ceil((rateLimiter.getResetTime(clientId) - Date.now()) / 1000),
        },
        {
          status: 429,
          headers: {
            "Retry-After": Math.ceil((rateLimiter.getResetTime(clientId) - Date.now()) / 1000).toString(),
            "X-RateLimit-Limit": "15",
            "X-RateLimit-Remaining": rateLimiter.getRemainingRequests(clientId).toString(),
            "X-RateLimit-Reset": rateLimiter.getResetTime(clientId).toString(),
          },
        },
      )
    }

    const { url } = await request.json()

    if (!url || typeof url !== "string") {
      logSecurityEvent("INVALID_INPUT", { url: typeof url }, request)
      return NextResponse.json({ error: "URL is required and must be a string" }, { status: 400 })
    }

    const sanitizedUrl = sanitizeUrl(url)
    const validation = validateUrl(sanitizedUrl)

    if (!validation.isValid) {
      logSecurityEvent("INVALID_URL", { url: sanitizedUrl, error: validation.error }, request)
      return NextResponse.json({ error: validation.error }, { status: 400 })
    }

    logSecurityEvent("ANALYSIS_REQUEST", { url: sanitizedUrl }, request)

    const features = extractFeatures(sanitizedUrl)

    const phishingScore = calculatePhishingScore(features, sanitizedUrl)
    const isPhishing = phishingScore > 0.5
    const confidence = Math.round((isPhishing ? phishingScore : 1 - phishingScore) * 100)

    const riskFactors = generateRiskFactors(features, sanitizedUrl)
    const suspiciousPatterns = generateSuspiciousPatterns(features, sanitizedUrl)

    const result: AnalysisResult = {
      url: sanitizedUrl,
      isPhishing,
      confidence,
      riskFactors,
      analysis: {
        domainAge:
          features.domainAge < 30
            ? `${Math.round(features.domainAge)} days`
            : features.domainAge < 365
              ? `${Math.round(features.domainAge / 30)} months`
              : `${Math.round(features.domainAge / 365)} years`,
        sslStatus: features.hasHttps ? "Valid HTTPS" : "No HTTPS/Invalid",
        reputation: isPhishing ? "Suspicious" : "Good",
        suspiciousPatterns,
      },
    }

    logSecurityEvent(
      "ANALYSIS_COMPLETE",
      {
        url: sanitizedUrl,
        isPhishing,
        confidence,
        riskFactorCount: riskFactors.length,
      },
      request,
    )

    const processingTime = 1000 + Math.random() * 1000
    await new Promise((resolve) => setTimeout(resolve, processingTime))

    const response = NextResponse.json(result)
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.set("X-RateLimit-Remaining", rateLimiter.getRemainingRequests(clientId).toString())

    return response
  } catch (error) {
    logSecurityEvent("ANALYSIS_ERROR", { error: error instanceof Error ? error.message : "Unknown error" }, request)
    console.error("Analysis error:", error)
    return NextResponse.json({ error: "Failed to analyze URL" }, { status: 500 })
  }
}

export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    },
  })
}
