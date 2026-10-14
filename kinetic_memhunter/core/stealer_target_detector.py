"""Kinetic Stealer Target and Application Profile Detector."""

from __future__ import annotations

import re

TARGETED_BROWSER_KEYWORDS = [
    (b"Google\\Chrome\\User Data", "Google Chrome"),
    (b"Microsoft\\Edge\\User Data", "Microsoft Edge"),
    (b"Brave-Browser\\User Data", "Brave Browser"),
    (b"Opera Software\\Opera Stable", "Opera Browser"),
    (b"Opera Software\\Opera GX Stable", "Opera GX"),
    (b"Vivaldi\\User Data", "Vivaldi Browser"),
    (b"Yandex\\YandexBrowser", "Yandex Browser"),
    (b"7Star\\7Star\\User Data", "7Star Browser"),
    (b"CentBrowser\\User Data", "CentBrowser"),
    (b"Chedot\\User Data", "Chedot Browser"),
    (b"Coowon\\Coowon\\User Data", "Coowon Browser"),
    (b"Elements Browser\\User Data", "Elements Browser"),
    (b"Fenrir Inc\\Sleipnir5", "Sleipnir Browser"),
    (b"liebao\\User Data", "Liebao Browser"),
    (b"Kometa\\User Data", "Kometa Browser"),
    (b"Orbitum\\User Data", "Orbitum Browser"),
    (b"Mozilla\\Firefox\\Profiles", "Mozilla Firefox"),
    (b"Waterfox\\Profiles", "Waterfox Browser"),
    (b"Thunderbird\\Profiles", "Mozilla Thunderbird"),
]

TARGETED_CREDENTIAL_FILES = [
    (b"Login Data", "Chromium Saved Logins (Login Data)"),
    (b"Web Data", "Chromium Autofill & Credit Cards (Web Data)"),
    (b"Cookies", "Chromium Network Cookies"),
    (b"Local State", "Chromium DPAPI / App-Bound Master Key"),
    (b"key4.db", "Gecko NSS Key Database (key4.db)"),
    (b"logins.json", "Gecko Saved Logins (logins.json)"),
    (b"places.sqlite", "Gecko Browser History & Bookmarks"),
    (b"formhistory.sqlite", "Gecko Autofill Forms"),
]

TARGETED_CLIENTS = [
    (b"FileZilla", "FileZilla FTP Client"),
    (b"WinSCP", "WinSCP SFTP/FTP Client"),
    (b"recentservers.xml", "FileZilla Stored Server Credentials"),
    (b"sitemanager.xml", "FileZilla Site Manager XML"),
    (b"winscp.ini", "WinSCP Session Configuration"),
    (b"Telegram Desktop", "Telegram Desktop Client"),
    (b"tdata", "Telegram Session Data (tdata)"),
    (b"Discord\\Local Storage", "Discord Session Storage"),
    (b"OpenVPN Connect", "OpenVPN Configuration"),
    (b"NordVPN", "NordVPN Client"),
    (b"ProtonVPN", "ProtonVPN Client"),
]

CRYPTO_WALLET_EXTENSIONS = [
    (b"nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask Wallet Extension"),
    (b"hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet Extension"),
    (b"fhbohimaelbohpjbbldcngcnapndodjp", "Binance Chain Wallet Extension"),
    (b"bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom Solana Wallet Extension"),
    (b"ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink Wallet Extension"),
    (b"fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin Wallet Extension"),
    (b"egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet Extension"),
]


class StealerTargetDetector:
    """Scans memory for targeted software, browsers, wallets, and credential store paths."""

    def __init__(self):
        # Path regex looking for specific user data paths
        self._path_pattern = re.compile(
            rb"[a-zA-Z]:\\[^\x00\r\n\t]{5,200}(?:Login Data|Cookies|Web Data|History|places\.sqlite|key4\.db|Local State|tdata)",
            re.IGNORECASE,
        )

    def scan(self, buffer: bytes) -> tuple[list[str], list[str]]:
        """Returns (malware_targets, targeted_paths)."""
        targets: set[str] = set()
        paths: set[str] = set()

        # 1. Targeted Browsers
        for pattern, name in TARGETED_BROWSER_KEYWORDS:
            if pattern in buffer:
                targets.add(name)

        # 2. Targeted Credential Stores & Files
        for pattern, name in TARGETED_CREDENTIAL_FILES:
            if pattern in buffer:
                targets.add(name)

        # 3. Targeted Desktop Clients
        for pattern, name in TARGETED_CLIENTS:
            if pattern in buffer:
                targets.add(name)

        # 4. Crypto Wallets
        for pattern, name in CRYPTO_WALLET_EXTENSIONS:
            if pattern in buffer:
                targets.add(name)

        # 5. Extract Concrete In-Memory Paths
        for match in self._path_pattern.finditer(buffer):
            try:
                p_str = match.group(0).decode("latin1").strip()
                if 10 <= len(p_str) <= 200:
                    paths.add(p_str)
            except Exception:
                continue

        return sorted(list(targets)), sorted(list(paths))
