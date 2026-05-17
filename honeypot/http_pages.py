"""Static bait pages served by the HTTP honeypot.

These are plain HTML strings — convincing decoys for common attack targets
(admin panels, CMS logins, exposed secrets). They contain no scripts and no
server-side logic; the honeypot only ever returns them verbatim.
"""

from __future__ import annotations

_LOGIN_FORM = """\
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:Arial,sans-serif;background:#f2f3f5;margin:0}}
.box{{width:320px;margin:90px auto;background:#fff;border:1px solid #d8dadf;
border-radius:4px;padding:28px}}h2{{margin:0 0 18px;font-size:20px;color:#222}}
input{{width:100%;padding:9px;margin:6px 0;border:1px solid #ccc;
border-radius:3px;box-sizing:border-box}}
button{{width:100%;padding:10px;margin-top:10px;background:#1f6feb;color:#fff;
border:0;border-radius:3px;cursor:pointer}}.err{{color:#b00;font-size:13px}}</style>
</head>
<body><div class="box"><h2>{title}</h2>{message}
<form method="POST" action="{action}">
<input type="text" name="username" placeholder="Username" autofocus>
<input type="password" name="password" placeholder="Password">
<button type="submit">Sign in</button></form></div></body></html>
"""

_INVALID = '<p class="err">Invalid username or password.</p>'


def login_page(title: str, action: str, *, invalid: bool = False) -> str:
    """Render a generic login page; ``invalid=True`` shows a credentials error."""
    return _LOGIN_FORM.format(
        title=title,
        action=action,
        message=_INVALID if invalid else "",
    )


# --- Page table -------------------------------------------------------------
# Each entry: path -> (content_type, body). Login paths are rendered on demand
# so the POST handler can re-serve them with an error message.

INDEX_HTML = """\
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Apache2 Ubuntu Default Page</title>
<style>body{font-family:Arial,sans-serif;margin:0;color:#222}
.head{background:#e0e0e0;padding:18px 40px;border-bottom:1px solid #b0b0b0}
.body{padding:24px 40px}h1{font-size:24px}code{background:#f0f0f0;padding:2px 4px}</style>
</head><body>
<div class="head"><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p></div>
<div class="body">
<p>This is the default welcome page used to test the correct operation of the
Apache2 server after installation on Ubuntu systems.</p>
<p>If you can read this page, it means that the Apache HTTP server installed at
this site is working properly. You should <strong>replace this file</strong>
(located at <code>/var/www/html/index.html</code>) before continuing to operate
your HTTP server.</p>
<p>The configuration layout for an Apache2 web server installation on Ubuntu
systems is referenced in <code>/etc/apache2/apache2.conf</code>.</p>
</div></body></html>
"""

ENV_BODY = """\
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:8Sd0vN1qXk9pPbR2tYwZ3aF5gH7jK9mN1oP3qR5sT7u=
APP_DEBUG=false
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_prod
DB_USERNAME=app_user
DB_PASSWORD=changeme

REDIS_HOST=127.0.0.1
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
"""

GIT_CONFIG_BODY = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/example/app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

API_JSON = '{"name":"app-api","version":"2.4.1","status":"ok","endpoints":["/api/v1"]}'

CGI_BODY = """\
<!doctype html><html><head><title>403 Forbidden</title></head>
<body><h1>Forbidden</h1><p>You don't have permission to access this resource.</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server</address></body></html>
"""

NOT_FOUND_BODY = """\
<!doctype html><html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server</address></body></html>
"""

# Paths treated as login endpoints — a POST here is parsed for credentials.
LOGIN_PATHS: dict[str, str] = {
    "/admin": "Admin Console",
    "/login": "Sign In",
    "/wp-login.php": "WordPress",
    "/wp-admin": "WordPress",
    "/phpmyadmin": "phpMyAdmin",
}

# Static (non-login) bait paths -> (content_type, body).
STATIC_PAGES: dict[str, tuple[str, str]] = {
    "/": ("text/html; charset=utf-8", INDEX_HTML),
    "/.env": ("text/plain; charset=utf-8", ENV_BODY),
    "/.git/config": ("text/plain; charset=utf-8", GIT_CONFIG_BODY),
    "/api": ("application/json", API_JSON),
    "/cgi-bin/": ("text/html; charset=utf-8", CGI_BODY),
}
