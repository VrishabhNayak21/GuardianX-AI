// Security utilities for input validation and sanitization

export function validateUrl(url: string): { isValid: boolean; error?: string } {
  // Basic length check
  if (!url || url.length === 0) {
    return { isValid: false, error: "URL cannot be empty" }
  }

  if (url.length > 2048) {
    return { isValid: false, error: "URL is too long (max 2048 characters)" }
  }

  // Check for malicious patterns
  const maliciousPatterns = [
    /javascript:/i,
    /data:/i,
    /vbscript:/i,
    /file:/i,
    /<script/i,
    /onload=/i,
    /onerror=/i,
    /onclick=/i,
  ]

  for (const pattern of maliciousPatterns) {
    if (pattern.test(url)) {
      return { isValid: false, error: "URL contains potentially malicious content" }
    }
  }

  // Try to parse as URL
  try {
    const urlObj = new URL(url)

    // Only allow http and https protocols
    if (!["http:", "https:"].includes(urlObj.protocol)) {
      return { isValid: false, error: "Only HTTP and HTTPS URLs are allowed" }
    }

    // Check for suspicious localhost/private IP patterns
    const hostname = urlObj.hostname.toLowerCase()
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("10.") ||
      hostname.startsWith("172.")
    ) {
      return { isValid: false, error: "Private/local URLs are not allowed" }
    }

    return { isValid: true }
  } catch {
    return { isValid: false, error: "Invalid URL format" }
  }
}

export function sanitizeUrl(url: string): string {
  // Remove any potential XSS characters and normalize
  return url
    .trim()
    .replace(/[<>'"]/g, "") // Remove potential XSS characters
    .replace(/\s+/g, "") // Remove whitespace
}

export function getClientIdentifier(request: Request): string {
  // Get client identifier for rate limiting
  const forwarded = request.headers.get("x-forwarded-for")
  const realIp = request.headers.get("x-real-ip")
  const clientIp = forwarded?.split(",")[0] || realIp || "unknown"

  return clientIp
}

export function logSecurityEvent(event: string, details: any, request: Request): void {
  const timestamp = new Date().toISOString()
  const clientId = getClientIdentifier(request)

  console.log(`[SECURITY] ${timestamp} - ${event}`, {
    clientId,
    userAgent: request.headers.get("user-agent"),
    ...details,
  })
}
