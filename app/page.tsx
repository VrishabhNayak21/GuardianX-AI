"use client"

import { useState } from "react"
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Loader2,
  Globe,
  Lock,
  Zap,
  TrendingUp,
  Users,
  Plus,
  Minus,
  Sparkles,
  Target,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface DetectionResult {
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

export default function PhishingDetector() {
  const [url, setUrl] = useState("")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<DetectionResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const analyzeUrl = async () => {
    if (!url.trim()) return

    setIsAnalyzing(true)
    setError(null)

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url.trim() }),
      })

      if (!response.ok) {
        const errorData = await response.json()

        if (response.status === 429) {
          const retryAfter = errorData.retryAfter || 60
          throw new Error(`Too many requests. Please wait ${retryAfter} seconds before trying again.`)
        }

        throw new Error(errorData.error || "Analysis failed")
      }

      const analysisResult: DetectionResult = await response.json()
      setResult(analysisResult)
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred")
    } finally {
      setIsAnalyzing(false)
    }
  }

  const resetAnalysis = () => {
    setResult(null)
    setUrl("")
    setError(null)
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border bg-card backdrop-blur-xl shadow-lg">
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center gap-6">
            <div className="relative">
              <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-primary shadow-2xl animate-pulse">
                <Shield className="w-8 h-8 text-primary-foreground" />
              </div>
              <div className="absolute -top-1 -right-1 w-6 h-6 bg-accent rounded-full flex items-center justify-center animate-bounce">
                <Sparkles className="w-3 h-3 text-accent-foreground" />
              </div>
            </div>
            <div>
              <h1 className="text-3xl font-bold text-foreground tracking-tight">GuardianX AI</h1>
              <p className="text-base text-muted-foreground font-semibold">Advanced URL Security Analysis Platform</p>
            </div>
            <div className="ml-auto flex items-center gap-8">
              <div className="hidden lg:flex items-center gap-8 text-sm font-medium">
                <div className="flex items-center gap-2 px-4 py-2 bg-muted rounded-full border border-border">
                  <Users className="w-4 h-4 text-primary" />
                  <span className="text-muted-foreground">50K+ Users</span>
                </div>
                <div className="flex items-center gap-2 px-4 py-2 bg-muted rounded-full border border-border">
                  <Target className="w-4 h-4 text-primary" />
                  <span className="text-muted-foreground">99.2% Accuracy</span>
                </div>
                <div className="flex items-center gap-2 px-4 py-2 bg-muted rounded-full border border-border">
                  <TrendingUp className="w-4 h-4 text-primary" />
                  <span className="text-muted-foreground">1M+ URLs Analyzed</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-16">
        {!result ? (
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-16">
              <div className="relative inline-flex items-center justify-center mb-8">
                <div className="w-24 h-24 rounded-3xl bg-primary shadow-2xl flex items-center justify-center animate-pulse">
                  <Shield className="w-12 h-12 text-primary-foreground" />
                </div>
                <div className="absolute -top-2 -right-2 w-8 h-8 bg-accent rounded-full flex items-center justify-center animate-bounce">
                  <Sparkles className="w-4 h-4 text-accent-foreground" />
                </div>
                <div className="absolute inset-0 rounded-3xl bg-primary/20 blur-xl scale-150 animate-pulse"></div>
              </div>
              <h2 className="text-5xl md:text-6xl font-bold mb-6 text-balance leading-tight">
                <span className="text-foreground">Protect Yourself from</span>
                <span className="block text-primary font-extrabold">Phishing Attacks</span>
              </h2>
              <p className="text-xl text-muted-foreground text-pretty max-w-3xl mx-auto leading-relaxed font-medium">
                Our cutting-edge AI system analyzes URLs in real-time to detect malicious websites and keep you safe
                online with industry-leading accuracy and lightning-fast results.
              </p>
            </div>

            <Card className="mb-16 shadow-2xl border-0 bg-card backdrop-blur-xl overflow-hidden">
              <div className="absolute inset-0 bg-primary/5"></div>
              <CardHeader className="pb-6 relative">
                <CardTitle className="flex items-center gap-4 text-2xl text-card-foreground">
                  <div className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center shadow-lg">
                    <Globe className="w-6 h-6 text-primary-foreground" />
                  </div>
                  URL Security Analysis
                </CardTitle>
                <CardDescription className="text-lg text-muted-foreground">
                  Paste any URL below to check if it's safe or potentially malicious
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-8 relative">
                <div className="flex gap-4">
                  <div className="relative flex-1">
                    <Input
                      placeholder="https://example.com or paste any suspicious URL..."
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="h-14 text-lg border-2 border-border focus:border-primary transition-all duration-300 bg-input backdrop-blur-sm"
                      onKeyDown={(e) => e.key === "Enter" && analyzeUrl()}
                    />
                    {isAnalyzing && <div className="absolute inset-0 bg-primary/10 rounded-lg animate-pulse"></div>}
                  </div>
                  <Button
                    onClick={analyzeUrl}
                    disabled={!url.trim() || isAnalyzing}
                    className="h-14 px-10 text-lg font-bold bg-primary hover:bg-primary/90 shadow-xl hover:shadow-2xl transition-all duration-300 hover:scale-105 border-0"
                  >
                    {isAnalyzing ? (
                      <>
                        <Loader2 className="w-6 h-6 mr-3 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Zap className="w-6 h-6 mr-3" />
                        Analyze URL
                      </>
                    )}
                  </Button>
                </div>

                {error && (
                  <Alert className="border-destructive/50 bg-destructive/5 shadow-lg">
                    <AlertTriangle className="w-6 h-6 text-destructive" />
                    <AlertDescription className="text-destructive font-semibold text-base">{error}</AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>

            <Tabs defaultValue="advantages" className="mb-16">
              <TabsList className="grid w-full grid-cols-2 mb-10 h-14 bg-card backdrop-blur-xl border border-border">
                <TabsTrigger
                  value="advantages"
                  className="flex items-center gap-3 text-base font-semibold h-12 text-card-foreground data-[state=active]:text-primary"
                >
                  <Plus className="w-5 h-5" />
                  Advantages
                </TabsTrigger>
                <TabsTrigger
                  value="disadvantages"
                  className="flex items-center gap-3 text-base font-semibold h-12 text-card-foreground data-[state=active]:text-primary"
                >
                  <Minus className="w-5 h-5" />
                  Limitations
                </TabsTrigger>
              </TabsList>

              <TabsContent value="advantages">
                <div className="grid md:grid-cols-2 gap-8">
                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-primary/5 group-hover:bg-primary/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-primary flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <Zap className="w-6 h-6 text-primary-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">Real-Time Detection</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        Instant analysis using advanced AI algorithms that process URLs in milliseconds, providing
                        immediate security feedback with unmatched speed.
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-accent/5 group-hover:bg-accent/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-accent flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <Shield className="w-6 h-6 text-accent-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">High Accuracy</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        99.2% detection accuracy with continuous learning from global threat intelligence and advanced
                        machine learning models trained on millions of URLs.
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-secondary/5 group-hover:bg-secondary/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-secondary flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <Lock className="w-6 h-6 text-secondary-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">Privacy Protected</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        No personal data storage, secure analysis process, and complete privacy protection for all users
                        with enterprise-grade security.
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-primary/5 group-hover:bg-primary/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-primary flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <Globe className="w-6 h-6 text-primary-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">Comprehensive Analysis</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        Multi-layered security analysis including domain reputation, SSL verification, pattern
                        recognition, and behavioral analysis for complete protection.
                      </p>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              <TabsContent value="disadvantages">
                <div className="grid md:grid-cols-2 gap-8">
                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-destructive/5 group-hover:bg-destructive/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-destructive flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <AlertTriangle className="w-6 h-6 text-destructive-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">False Positives</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        Legitimate websites may occasionally be flagged as suspicious due to certain URL patterns or
                        hosting configurations that trigger security alerts.
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-destructive/5 group-hover:bg-destructive/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-destructive flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <Globe className="w-6 h-6 text-destructive-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">New Threats</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        Brand new phishing sites may not be immediately detected until the AI model learns from updated
                        threat data and incorporates new attack patterns.
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-destructive/5 group-hover:bg-destructive/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-destructive flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <Loader2 className="w-6 h-6 text-destructive-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">Rate Limiting</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        Analysis requests are limited to prevent abuse, which may temporarily restrict usage during
                        high-volume periods or suspicious activity detection.
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="border-0 bg-card backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden group">
                    <div className="absolute inset-0 bg-destructive/5 group-hover:bg-destructive/10 transition-all duration-300"></div>
                    <CardContent className="pt-8 relative">
                      <div className="flex items-center gap-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-destructive flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                          <Globe className="w-6 h-6 text-destructive-foreground" />
                        </div>
                        <h3 className="font-bold text-xl text-card-foreground">URL-Based Analysis</h3>
                      </div>
                      <p className="text-muted-foreground leading-relaxed text-base">
                        Analysis focuses on URL patterns and metadata; sophisticated phishing sites with
                        legitimate-looking URLs may require additional verification methods.
                      </p>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>

            <div className="grid md:grid-cols-3 gap-10">
              <Card className="group hover:shadow-2xl transition-all duration-500 hover:-translate-y-2 border-0 bg-card backdrop-blur-xl overflow-hidden">
                <div className="absolute inset-0 bg-primary/5 group-hover:bg-primary/10 transition-all duration-500"></div>
                <CardContent className="pt-10 relative">
                  <div className="flex items-center gap-5 mb-6">
                    <div className="w-14 h-14 rounded-2xl bg-primary flex items-center justify-center group-hover:scale-110 transition-transform duration-500 shadow-xl">
                      <Zap className="w-7 h-7 text-primary-foreground" />
                    </div>
                    <h3 className="font-bold text-xl text-card-foreground">Real-time Analysis</h3>
                  </div>
                  <p className="text-muted-foreground leading-relaxed text-base">
                    Instant AI-powered detection using advanced machine learning models trained on millions of URLs with
                    lightning-fast processing speeds.
                  </p>
                </CardContent>
              </Card>

              <Card className="group hover:shadow-2xl transition-all duration-500 hover:-translate-y-2 border-0 bg-card backdrop-blur-xl overflow-hidden">
                <div className="absolute inset-0 bg-secondary/5 group-hover:bg-secondary/10 transition-all duration-500"></div>
                <CardContent className="pt-10 relative">
                  <div className="flex items-center gap-5 mb-6">
                    <div className="w-14 h-14 rounded-2xl bg-secondary flex items-center justify-center group-hover:scale-110 transition-transform duration-500 shadow-xl">
                      <Lock className="w-7 h-7 text-secondary-foreground" />
                    </div>
                    <h3 className="font-bold text-xl text-card-foreground">Privacy First</h3>
                  </div>
                  <p className="text-muted-foreground leading-relaxed text-base">
                    Your URLs are analyzed securely without storing personal data or browsing history, ensuring complete
                    privacy protection.
                  </p>
                </CardContent>
              </Card>

              <Card className="group hover:shadow-2xl transition-all duration-500 hover:-translate-y-2 border-0 bg-card backdrop-blur-xl overflow-hidden">
                <div className="absolute inset-0 bg-accent/5 group-hover:bg-accent/10 transition-all duration-500"></div>
                <CardContent className="pt-10 relative">
                  <div className="flex items-center gap-5 mb-6">
                    <div className="w-14 h-14 rounded-2xl bg-accent flex items-center justify-center group-hover:scale-110 transition-transform duration-500 shadow-xl">
                      <Shield className="w-7 h-7 text-accent-foreground" />
                    </div>
                    <h3 className="font-bold text-xl text-card-foreground">99.2% Accuracy</h3>
                  </div>
                  <p className="text-muted-foreground leading-relaxed text-base">
                    Industry-leading detection rates with continuous learning from global threat intelligence and
                    advanced pattern recognition.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        ) : (
          <div className="max-w-5xl mx-auto">
            <div className="flex items-center justify-between mb-8">
              <h2 className="text-3xl font-bold text-foreground">Analysis Results</h2>
              <Button
                variant="outline"
                onClick={resetAnalysis}
                className="hover:bg-accent hover:text-accent-foreground transition-colors bg-transparent"
              >
                Analyze Another URL
              </Button>
            </div>

            <Alert
              className={`mb-8 border-2 shadow-lg ${
                result.isPhishing ? "border-destructive/50 bg-destructive/5" : "border-accent/50 bg-accent/5"
              }`}
            >
              <div className="flex items-center gap-4">
                <div
                  className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                    result.isPhishing ? "bg-destructive/10" : "bg-accent/10"
                  }`}
                >
                  {result.isPhishing ? (
                    <AlertTriangle className="w-6 h-6 text-destructive" />
                  ) : (
                    <CheckCircle className="w-6 h-6 text-accent" />
                  )}
                </div>
                <div className="flex-1">
                  <h3 className="font-bold text-lg mb-2 text-foreground">
                    {result.isPhishing ? "⚠️ Phishing Detected!" : "✅ URL Appears Safe"}
                  </h3>
                  <AlertDescription className="text-base text-muted-foreground">
                    {result.isPhishing
                      ? "This URL shows signs of being a phishing attempt. Avoid clicking or entering personal information."
                      : "Our analysis indicates this URL is likely legitimate and safe to visit."}
                  </AlertDescription>
                </div>
                <Badge
                  variant={result.isPhishing ? "destructive" : "default"}
                  className="text-base px-4 py-2 font-semibold"
                >
                  {result.confidence}% Confidence
                </Badge>
              </div>
            </Alert>

            <div className="grid lg:grid-cols-2 gap-8">
              <Card className="shadow-xl border-0 bg-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-3 text-xl text-card-foreground">
                    <Globe className="w-6 h-6 text-primary" />
                    URL Information
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <label className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                      Analyzed URL
                    </label>
                    <p className="text-sm font-mono bg-muted/50 p-3 rounded-lg mt-2 break-all border border-border">
                      {result.url}
                    </p>
                  </div>
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <label className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                        Domain Age
                      </label>
                      <p className="text-base mt-2 font-medium text-card-foreground">{result.analysis.domainAge}</p>
                    </div>
                    <div>
                      <label className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                        SSL Status
                      </label>
                      <p className="text-base mt-2 font-medium text-card-foreground">{result.analysis.sslStatus}</p>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                      Reputation
                    </label>
                    <p className="text-base mt-2 font-medium text-card-foreground">{result.analysis.reputation}</p>
                  </div>
                </CardContent>
              </Card>

              <Card className="shadow-xl border-0 bg-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-3 text-xl text-card-foreground">
                    <AlertTriangle className="w-6 h-6 text-destructive" />
                    Risk Analysis
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <label className="text-sm font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">
                      Risk Factors
                    </label>
                    <div className="space-y-3">
                      {result.riskFactors.length > 0 ? (
                        result.riskFactors.map((factor, index) => (
                          <div
                            key={index}
                            className="flex items-center gap-3 p-3 bg-destructive/5 rounded-lg border border-destructive/20"
                          >
                            <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0" />
                            <span className="text-sm font-medium text-card-foreground">{factor}</span>
                          </div>
                        ))
                      ) : (
                        <p className="text-sm text-muted-foreground italic">No significant risk factors detected</p>
                      )}
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">
                      Suspicious Patterns
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {result.analysis.suspiciousPatterns.length > 0 ? (
                        result.analysis.suspiciousPatterns.map((pattern, index) => (
                          <Badge key={index} variant="outline" className="px-3 py-1 font-medium">
                            {pattern}
                          </Badge>
                        ))
                      ) : (
                        <p className="text-sm text-muted-foreground italic">No suspicious patterns found</p>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
