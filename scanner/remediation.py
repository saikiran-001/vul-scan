"""
remediation.py -- the "How to fix it" database (Week 3 deliverable).

WHY THIS FILE EXISTS
--------------------
A scanner that only says "CSP is missing" is not useful to a beginner.
Every failed check should answer three questions:

  1. why      -- what can an attacker do because of this?
  2. fix      -- what should the owner do, in plain English?
  3. snippet  -- copy-pasteable configuration for the most common servers.

The dictionary is keyed by the check id used in headers_check.py,
ssl_check.py and cms_check.py. The engine attaches the matching entry to
each check, so the UI and the PDF never need to know these strings.
"""

REMEDIATION = {
    # ---------------------------------------------------------------- headers
    "csp": {
        "why": "Without CSP, any injected <script> (XSS) runs with full access to the page, "
               "cookies and localStorage.",
        "fix": "Start with a report-only policy, fix the violations it reports, then enforce it. "
               "Avoid 'unsafe-inline'.",
        "snippet": (
            "# nginx\n"
            "add_header Content-Security-Policy \"default-src 'self'; "
            "img-src 'self' data:; script-src 'self'; style-src 'self'\" always;"
        ),
        "docs": "https://developer.mozilla.org/docs/Web/HTTP/CSP",
    },
    "xfo": {
        "why": "Without X-Frame-Options another site can load yours inside an invisible iframe "
               "and trick users into clicking buttons (clickjacking).",
        "fix": "Send DENY, or SAMEORIGIN if you legitimately frame your own pages.",
        "snippet": "# nginx\nadd_header X-Frame-Options \"SAMEORIGIN\" always;",
        "docs": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "hsts": {
        "why": "Without HSTS the first request can be downgraded from HTTPS to HTTP, "
               "letting an attacker on the network read or modify it.",
        "fix": "Send HSTS with max-age of at least six months. Only enable it once HTTPS works "
               "on every subdomain, because it is hard to undo.",
        "snippet": "# nginx\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
        "docs": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "xcto": {
        "why": "Browsers may guess that an uploaded file is JavaScript and execute it.",
        "fix": "Send nosniff so the browser trusts the declared Content-Type.",
        "snippet": "# nginx\nadd_header X-Content-Type-Options \"nosniff\" always;",
        "docs": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "referrer": {
        "why": "Full URLs (sometimes containing tokens) leak to third-party sites through Referer.",
        "fix": "Use strict-origin-when-cross-origin, the modern default.",
        "snippet": "# nginx\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        "docs": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "permissions": {
        "why": "Any embedded third-party script can ask for the camera, microphone or location.",
        "fix": "Disable the features you do not use.",
        "snippet": "# nginx\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
        "docs": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
    },

    # ---------------------------------------------------------------- TLS
    "https": {
        "why": "Plain HTTP sends passwords and cookies in clear text; anyone on the Wi-Fi can read them.",
        "fix": "Install a free certificate (Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
        "snippet": (
            "# nginx\n"
            "server {\n"
            "    listen 80;\n"
            "    server_name example.com;\n"
            "    return 301 https://$host$request_uri;\n"
            "}"
        ),
        "docs": "https://letsencrypt.org/getting-started/",
    },
    "cert": {
        "why": "An untrusted certificate triggers browser warnings, so visitors learn to click through "
               "security errors -- and attackers can impersonate the site.",
        "fix": "Use a certificate from a public CA, make sure the hostname matches, and include the "
               "full intermediate chain.",
        "snippet": "# test the chain and the name\nopenssl s_client -connect example.com:443 -servername example.com",
        "docs": "https://www.ssllabs.com/ssltest/",
    },
    "expiry": {
        "why": "An expired certificate breaks the site for every visitor until it is renewed.",
        "fix": "Renew automatically and monitor the expiry date.",
        "snippet": "# certbot renews automatically via a timer/cron job\nsudo certbot renew --dry-run",
        "docs": "https://eff-certbot.readthedocs.io/",
    },
    "tls": {
        "why": "TLS 1.0/1.1 are deprecated and have known weaknesses.",
        "fix": "Allow only TLS 1.2 and 1.3 in your server configuration.",
        "snippet": "# nginx\nssl_protocols TLSv1.2 TLSv1.3;",
        "docs": "https://ssl-config.mozilla.org/",
    },
    "cipher": {
        "why": "Weak ciphers can be broken, exposing the traffic they protect.",
        "fix": "Use a modern cipher list; let Mozilla's generator pick one for you.",
        "snippet": "# nginx\nssl_prefer_server_ciphers off;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';",
        "docs": "https://ssl-config.mozilla.org/",
    },

    # ---------------------------------------------------------------- CMS
    "cms": {
        "why": "Outdated CMS versions have publicly known vulnerabilities; bots scan for them constantly.",
        "fix": "Update the core, themes and plugins, and enable automatic minor updates. "
               "Back up first, then update in a staging copy.",
        "snippet": (
            "# WordPress (WP-CLI)\n"
            "wp core update && wp plugin update --all && wp theme update --all\n"
            "# Drupal (Composer)\n"
            "composer update drupal/core-recommended --with-dependencies"
        ),
        "docs": "https://wordpress.org/support/article/updating-wordpress/",
    },
    "server": {
        "why": "Version banners tell attackers exactly which exploit to try first.",
        "fix": "Hide the version in the Server header. This is defence in depth, not a fix by itself.",
        "snippet": "# nginx\nserver_tokens off;\n\n# Apache\nServerTokens Prod\nServerSignature Off",
        "docs": "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
    },
}


def for_check(check_id: str) -> dict:
    """Look up remediation text, returning an empty dict for unknown ids."""

    return REMEDIATION.get(check_id, {})   # .get avoids a KeyError for future checks
