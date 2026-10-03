PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        "severity": "critical",
    },
    {
        "name": "AWS Secret Access Key",
        "regex": r"(?i)aws(.{0,20})?(secret|access).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]",
        "severity": "critical",
    },
    {
        "name": "Google API Key",
        "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "severity": "high",
    },
    {
        "name": "Google OAuth Client ID",
        "regex": r"\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b",
        "severity": "medium",
    },
    {
        "name": "Slack Token",
        "regex": r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",
        "severity": "critical",
    },
    {
        "name": "Slack Webhook",
        "regex": r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
        "severity": "high",
    },
    {
        "name": "GitHub Token",
        "regex": r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b",
        "severity": "critical",
    },
    {
        "name": "GitLab Token",
        "regex": r"\bglpat-[0-9A-Za-z\-_]{20,}\b",
        "severity": "critical",
    },
    {
        "name": "Stripe Secret Key",
        "regex": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
        "severity": "critical",
    },
    {
        "name": "Stripe Publishable Key",
        "regex": r"\bpk_live_[0-9a-zA-Z]{24,}\b",
        "severity": "medium",
    },
    {
        "name": "SendGrid API Key",
        "regex": r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        "severity": "high",
    },
    {
        "name": "Twilio Account SID",
        "regex": r"\bAC[0-9a-fA-F]{32}\b",
        "severity": "medium",
    },
    {
        "name": "Mailgun API Key",
        "regex": r"\bkey-[0-9a-zA-Z]{32}\b",
        "severity": "high",
    },
    {
        "name": "Heroku API Key",
        "regex": r"(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "high",
    },
    {
        "name": "JWT",
        "regex": r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        "severity": "high",
    },
    {
        "name": "Bearer Token",
        "regex": r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*",
        "severity": "medium",
    },
    {
        "name": "Basic Auth",
        "regex": r"(?i)authorization\s*[:=]\s*['\"]?basic\s+[A-Za-z0-9+/=]{16,}",
        "severity": "high",
    },
    {
        "name": "Private Key Block",
        "regex": r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
        "severity": "critical",
    },
    {
        "name": "Generic API Key Assignment",
        "regex": r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9\-_/+=]{16,64})['\"]",
        "severity": "medium",
    },
    {
        "name": "Generic Password Assignment",
        "regex": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{6,64})['\"]",
        "severity": "medium",
    },
    {
        "name": "Database URI",
        "regex": r"(?i)(mongodb|postgres|postgresql|mysql|redis|amqp)://[^\s'\"<>]{6,}",
        "severity": "high",
    },
    {
        "name": "Firebase URL",
        "regex": r"https://[a-z0-9\-]+\.firebaseio\.com",
        "severity": "medium",
    },
    {
        "name": "Firebase Config Key",
        "regex": r"(?i)apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
        "severity": "high",
    },
    {
        "name": "Cloudinary URL",
        "regex": r"cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[A-Za-z0-9\-_]+",
        "severity": "high",
    },
    {
        "name": "Discord Webhook",
        "regex": r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+",
        "severity": "medium",
    },
    {
        "name": "Telegram Bot Token",
        "regex": r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b",
        "severity": "high",
    },
    {
        "name": "Shopify Access Token",
        "regex": r"\bshpat_[a-fA-F0-9]{32}\b",
        "severity": "high",
    },
    {
        "name": "Shopify Shared Secret",
        "regex": r"\bshpss_[a-fA-F0-9]{32}\b",
        "severity": "high",
    },
    {
        "name": "Square Access Token",
        "regex": r"\bsq0atp-[0-9A-Za-z\-_]{22}\b",
        "severity": "high",
    },
    {
        "name": "Square OAuth Secret",
        "regex": r"\bsq0csp-[0-9A-Za-z\-_]{43}\b",
        "severity": "high",
    },
    {
        "name": "NPM Token",
        "regex": r"\bnpm_[A-Za-z0-9]{36}\b",
        "severity": "high",
    },
    {
        "name": "PyPI Token",
        "regex": r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b",
        "severity": "high",
    },
    {
        "name": "OpenAI API Key",
        "regex": r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
        "severity": "critical",
    },
    {
        "name": "Anthropic API Key",
        "regex": r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
        "severity": "critical",
    },
    {
        "name": "Hugging Face Token",
        "regex": r"\bhf_[A-Za-z0-9]{34,}\b",
        "severity": "high",
    },
]
