"""Outgoing email over SMTP - standard library only.

Optional, like every other integration: unconfigured (`ACT_SMTP_HOST` /
`ACT_SMTP_FROM` unset) means :meth:`EmailSender.send` is a logged no-op that
never raises. Used for password-reset links and, when `ACT_EMAIL_ALERTS` is on,
critical-attack alerts.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Optional, Tuple

from app.core.settings import Settings, get_settings

log = logging.getLogger("app.core.email")


@dataclass(frozen=True, slots=True)
class EmailSender:
    host: Optional[str]
    port: int
    username: Optional[str]
    password: Optional[str]
    sender: Optional[str]
    use_starttls: bool
    use_ssl: bool
    timeout: int

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None) -> "EmailSender":
        s = settings or get_settings()
        return cls(
            host=s.smtp_host, port=s.smtp_port,
            username=s.smtp_username, password=s.smtp_password,
            sender=s.smtp_from, use_starttls=s.smtp_starttls,
            use_ssl=s.smtp_ssl, timeout=s.smtp_timeout,
        )

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender)

    def send(
        self, to: str, subject: str, body: str, *, html: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """Returns ``(ok, error)``. Never raises."""
        if not self.configured:
            log.info("email not configured; would have sent %r to %s", subject, to)
            return False, "smtp not configured"
        if not to:
            return False, "no recipient"

        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = to
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="act")
        msg.set_content(body)
        if html:
            msg.add_alternative(html, subtype="html")

        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(self.host, self.port,
                                          timeout=self.timeout, context=context)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            with server:
                server.ehlo()
                if self.use_starttls and not self.use_ssl:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)
            log.info("email sent", extra={"to": to, "subject": subject})
            return True, None
        except Exception as exc:  # noqa: BLE001  (report, never raise)
            log.warning("email send failed: %s", exc)
            return False, str(exc)

    # ------------------------------------------------------------ templates #

    def send_password_reset(self, to: str, *, username: str, reset_url: str,
                            ttl_minutes: int) -> Tuple[bool, Optional[str]]:
        subject = "ACT - reset your password"
        body = (
            f"Hi {username},\n\n"
            f"A password reset was requested for your ACT account. Open this "
            f"link within {ttl_minutes} minutes to choose a new password:\n\n"
            f"    {reset_url}\n\n"
            f"If you did not request this, you can ignore this email - your "
            f"password will not change.\n"
        )
        return self.send(to, subject, body)

    def send_alert(self, to: str, *, actor: str, target: str, attack_type: str,
                   risk: int, summary: str) -> Tuple[bool, Optional[str]]:
        subject = f"ACT critical alert - {actor} ({risk}/100)"
        body = (
            f"ACT detected a critical attack.\n\n"
            f"  Attacker:    {actor}\n"
            f"  Target:      {target or 'monitored host'}\n"
            f"  Attack type: {attack_type}\n"
            f"  Risk score:  {risk}/100\n\n"
            f"{summary}\n"
        )
        return self.send(to, subject, body)
