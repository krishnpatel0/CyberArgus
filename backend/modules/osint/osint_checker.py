"""
OSINT Intelligence Engine — Multi-input enumeration with MLEW 4-gate scoring.

Combines techniques from Sherlock, Maigret, WhatsMyName, and Social-Analyzer:

  1. Multi-input detection  — auto-detect username/email/phone/name inputs
  2. Calibration requests   — compare response size against a random nonexistent user
  3. Dual-gate validation   — require BOTH status code AND content-string match
  4. Username presence check — verify the username appears in the page body
  5. Enhanced WAF detection  — expanded signature list with case-insensitive matching
  6. Redirect detection     — flag unexpected URL changes as non-matches
  7. MLEW 4-gate scoring    — Technical (20), Content (40), Correlation (30), Penalties
  8. Metadata extraction    — bio, avatar, location via OpenGraph + site-specific regex
  9. Recursive pivoting     — BFS expansion from discovered emails/@mentions in bios
 10. WhatsMyName integration — supplementary site database merged with Sherlock

Can search operator-mounted CSV breach files for authorized cross-reference.
"""

import hashlib
import html as html_module
import json
import os
import random
import re
import string
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote, urlparse

import requests

# ─── Constants ───

SHERLOCK_DATA_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    "master/sherlock_project/resources/data.json"
)

WMN_DATA_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/"
    "main/wmn-data.json"
)

# ─── Input type detection patterns ───

_EMAIL_RE = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
_PHONE_RE = re.compile(r'^[\+]?[\d\s\-\(\)]{10,15}$')

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) "
        "Gecko/20100101 Firefox/129.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

TIMEOUT = 15          # seconds per request
MAX_WORKERS = 30      # concurrent threads
CACHE_TTL = 3600      # re-fetch site list every hour
CONFIDENCE_THRESHOLD = 65   # minimum confidence % to report a result
DERIVED_CONFIDENCE_BONUS = 10
SITE_VALIDATION_TTL = 6 * 3600
REPORTABLE_TIERS = {"verified", "high"}
OSINT_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
VALIDATED_SITES_PATH = os.path.join(OSINT_CACHE_DIR, "osint_validated_sites.json")

# Module-level caches
_sites_cache = {"data": None, "fetched_at": 0}
_wmn_cache = {"data": None, "fetched_at": 0}
_calibration_cache = {}     # site_name -> {size, status, skeleton, timestamp}
_site_validation_cache = {} # site_name -> validation result
CALIBRATION_TTL = 600       # cache calibration results for 10 minutes

# ─── WAF / bot-detection signatures (expanded from Maigret + Cloudflare) ───

WAF_SIGNATURES = [
    "attention required! | cloudflare",
    "please wait... | cloudflare",
    "cf-browser-verification",
    "checking your browser",
    "checking if the site connection is secure",
    "enable javascript and cookies to continue",
    "access denied",
    "just a moment...",
    "ddos protection by",
    "sucuri website firewall",
    "incapsula incident",
    "sorry, you have been blocked",
    "ray id:",
    "performance & security by cloudflare",
    "please turn javascript on",
    "one more step",
    "why do i have to complete a captcha",
    "bot verification",
    "human verification",
    "pardon our interruption",
    "we need to verify that you are not a robot",
]

# ─── Sites known to return 200 for ANY username (high false-positive risk) ───

STRICT_SITES = {
    "Facebook", "Instagram", "LinkedIn", "TikTok", "Snapchat",
    "Threads", "Pinterest", "Notion", "Trello", "Canva",
    "Goodreads", "Strava", "Fiverr", "Upwork", "Swiggy",
    "Zomato", "Naukri", "eBay", "OpenSea", "Rarible",
    "Flipboard", "Cash App", "Venmo", "Dailymotion",
}

# ─── Username format rules per site (from Maigret) ───

USERNAME_RULES = {
    "GitHub": r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?$",
    "Twitter": r"^[a-zA-Z0-9_]{1,15}$",
    "Instagram": r"^[a-zA-Z0-9_.]{1,30}$",
    "Reddit": r"^[a-zA-Z0-9_\-]{3,20}$",
    "TikTok": r"^[a-zA-Z0-9_.]{2,24}$",
    "Twitch": r"^[a-zA-Z0-9_]{4,25}$",
    "YouTube": r"^[a-zA-Z0-9_\-]{1,}$",
    "Steam": r"^[a-zA-Z0-9_\-]{2,32}$",
    "GitLab": r"^[a-zA-Z0-9_.\-]{1,255}$",
    "HackerRank": r"^[a-zA-Z0-9_]{1,32}$",
    "LeetCode": r"^[a-zA-Z0-9_\-]{1,39}$",
    "Chess.com": r"^[a-zA-Z0-9_]{3,25}$",
    "Lichess": r"^[a-zA-Z0-9_\-]{2,20}$",
    "Telegram": r"^[a-zA-Z0-9_]{5,32}$",
}

# ─── Bundled fallback sites with presenceStrs for dual-gate validation ───

FALLBACK_SITES = {
    "GitHub": {"url": "https://www.github.com/{}", "urlMain": "https://www.github.com", "errorType": "status_code",
               "presenceStrs": ["repositories", "contributions", "followers"]},
    "Instagram": {"url": "https://www.instagram.com/{}/", "urlMain": "https://www.instagram.com", "errorType": "status_code"},
    "Twitter": {"url": "https://x.com/{}", "urlMain": "https://x.com", "errorType": "status_code"},
    "Facebook": {"url": "https://www.facebook.com/{}", "urlMain": "https://www.facebook.com", "errorType": "status_code"},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}", "urlMain": "https://www.linkedin.com", "errorType": "status_code"},
    "Reddit": {"url": "https://www.reddit.com/user/{}", "urlMain": "https://www.reddit.com", "errorType": "status_code",
               "presenceStrs": ["karma", "u/"]},
    "YouTube": {"url": "https://www.youtube.com/@{}", "urlMain": "https://www.youtube.com", "errorType": "status_code",
                "presenceStrs": ["subscribers", "channel"]},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "urlMain": "https://www.pinterest.com", "errorType": "status_code"},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "urlMain": "https://www.tiktok.com", "errorType": "status_code",
               "presenceStrs": ["followers", "following", "likes"]},
    "Snapchat": {"url": "https://www.snapchat.com/add/{}", "urlMain": "https://www.snapchat.com", "errorType": "status_code"},
    "Medium": {"url": "https://medium.com/@{}", "urlMain": "https://medium.com", "errorType": "status_code",
               "presenceStrs": ["followers"]},
    "Twitch": {"url": "https://www.twitch.tv/{}", "urlMain": "https://www.twitch.tv", "errorType": "status_code",
               "presenceStrs": ["channel", "stream"]},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "urlMain": "https://steamcommunity.com", "errorType": "status_code",
              "presenceStrs": ["profile_header", "playerAvatar"]},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "urlMain": "https://open.spotify.com", "errorType": "status_code"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "urlMain": "https://soundcloud.com", "errorType": "status_code",
                   "presenceStrs": ["followers", "tracks"]},
    "DeviantArt": {"url": "https://www.deviantart.com/{}", "urlMain": "https://www.deviantart.com", "errorType": "status_code"},
    "Flickr": {"url": "https://www.flickr.com/people/{}", "urlMain": "https://www.flickr.com", "errorType": "status_code"},
    "Behance": {"url": "https://www.behance.net/{}", "urlMain": "https://www.behance.net", "errorType": "status_code",
                "presenceStrs": ["appreciations", "project"]},
    "Dribbble": {"url": "https://dribbble.com/{}", "urlMain": "https://dribbble.com", "errorType": "status_code",
                 "presenceStrs": ["shots", "followers"]},
    "Vimeo": {"url": "https://vimeo.com/{}", "urlMain": "https://vimeo.com", "errorType": "status_code"},
    "Tumblr": {"url": "https://{}.tumblr.com", "urlMain": "https://www.tumblr.com", "errorType": "status_code"},
    "WordPress": {"url": "https://{}.wordpress.com", "urlMain": "https://wordpress.com", "errorType": "status_code"},
    "Blogger": {"url": "https://{}.blogspot.com", "urlMain": "https://www.blogger.com", "errorType": "status_code"},
    "Quora": {"url": "https://www.quora.com/profile/{}", "urlMain": "https://www.quora.com", "errorType": "status_code"},
    "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "urlMain": "https://news.ycombinator.com",
                   "errorType": "message", "errorMsg": "No such user."},
    "StackOverflow": {"url": "https://stackoverflow.com/users/?tab=accounts&SearchTerm={}", "urlMain": "https://stackoverflow.com",
                      "errorType": "message", "errorMsg": "No users matched your search"},
    "GitLab": {"url": "https://gitlab.com/{}", "urlMain": "https://gitlab.com", "errorType": "status_code"},
    "Bitbucket": {"url": "https://bitbucket.org/{}/", "urlMain": "https://bitbucket.org", "errorType": "status_code"},
    "Docker Hub": {"url": "https://hub.docker.com/u/{}", "urlMain": "https://hub.docker.com",
                   "urlProbe": "https://hub.docker.com/v2/users/{}", "errorType": "status_code"},
    "npm": {"url": "https://www.npmjs.com/~{}", "urlMain": "https://www.npmjs.com", "errorType": "status_code"},
    "PyPI": {"url": "https://pypi.org/user/{}", "urlMain": "https://pypi.org", "errorType": "status_code"},
    "Kaggle": {"url": "https://www.kaggle.com/{}", "urlMain": "https://www.kaggle.com", "errorType": "status_code"},
    "HackerRank": {"url": "https://www.hackerrank.com/{}", "urlMain": "https://www.hackerrank.com", "errorType": "status_code"},
    "LeetCode": {"url": "https://leetcode.com/{}", "urlMain": "https://leetcode.com", "errorType": "status_code"},
    "Codepen": {"url": "https://codepen.io/{}", "urlMain": "https://codepen.io", "errorType": "status_code"},
    "Replit": {"url": "https://replit.com/@{}", "urlMain": "https://replit.com", "errorType": "status_code"},
    "Codeforces": {"url": "https://codeforces.com/profile/{}", "urlMain": "https://codeforces.com", "errorType": "status_code",
                   "presenceStrs": ["Contribution", "Rating"]},
    "HuggingFace": {"url": "https://huggingface.co/{}", "urlMain": "https://huggingface.co", "errorType": "status_code"},
    "Keybase": {"url": "https://keybase.io/{}", "urlMain": "https://keybase.io", "errorType": "status_code"},
    "About.me": {"url": "https://about.me/{}", "urlMain": "https://about.me", "errorType": "status_code"},
    "Gravatar": {"url": "https://en.gravatar.com/{}", "urlMain": "https://en.gravatar.com", "errorType": "status_code"},
    "ProductHunt": {"url": "https://www.producthunt.com/@{}", "urlMain": "https://www.producthunt.com", "errorType": "status_code"},
    "Patreon": {"url": "https://www.patreon.com/{}", "urlMain": "https://www.patreon.com", "errorType": "status_code"},
    "BuyMeACoffee": {"url": "https://buymeacoffee.com/{}", "urlMain": "https://buymeacoffee.com", "errorType": "status_code"},
    "Ko-fi": {"url": "https://ko-fi.com/{}", "urlMain": "https://ko-fi.com", "errorType": "status_code"},
    "Telegram": {"url": "https://t.me/{}", "urlMain": "https://t.me", "errorType": "status_code"},
    "Discord": {"url": "https://discord.com", "urlMain": "https://discord.com",
                "urlProbe": "https://discord.com/api/v9/unique-username/username-attempt-unauthed",
                "request_method": "POST", "request_payload": {"username": "{}"},
                "errorType": "message", "errorMsg": "\"taken\": false"},
    "Mastodon": {"url": "https://mastodon.social/@{}", "urlMain": "https://mastodon.social", "errorType": "status_code"},
    "Threads": {"url": "https://www.threads.net/@{}", "urlMain": "https://www.threads.net", "errorType": "status_code"},
    "Bluesky": {"url": "https://bsky.app/profile/{}.bsky.social", "urlMain": "https://bsky.app", "errorType": "status_code"},
    "Imgur": {"url": "https://imgur.com/user/{}", "urlMain": "https://imgur.com", "errorType": "status_code"},
    "9GAG": {"url": "https://9gag.com/u/{}", "urlMain": "https://9gag.com", "errorType": "status_code"},
    "Dailymotion": {"url": "https://www.dailymotion.com/{}", "urlMain": "https://www.dailymotion.com", "errorType": "status_code"},
    "Fiverr": {"url": "https://www.fiverr.com/{}", "urlMain": "https://www.fiverr.com", "errorType": "status_code"},
    "Freelancer": {"url": "https://www.freelancer.com/u/{}", "urlMain": "https://www.freelancer.com", "errorType": "status_code"},
    "Upwork": {"url": "https://www.upwork.com/freelancers/~{}", "urlMain": "https://www.upwork.com", "errorType": "status_code"},
    "Goodreads": {"url": "https://www.goodreads.com/{}", "urlMain": "https://www.goodreads.com", "errorType": "status_code"},
    "Last.fm": {"url": "https://www.last.fm/user/{}", "urlMain": "https://www.last.fm", "errorType": "status_code",
                "presenceStrs": ["scrobbles", "listening"]},
    "MyAnimeList": {"url": "https://myanimelist.net/profile/{}", "urlMain": "https://myanimelist.net", "errorType": "status_code"},
    "AniList": {"url": "https://anilist.co/user/{}", "urlMain": "https://anilist.co", "errorType": "status_code"},
    "Roblox": {"url": "https://www.roblox.com/user.aspx?username={}", "urlMain": "https://www.roblox.com", "errorType": "status_code"},
    "Chess.com": {"url": "https://www.chess.com/member/{}", "urlMain": "https://www.chess.com", "errorType": "status_code",
                  "presenceStrs": ["rating", "games"]},
    "Lichess": {"url": "https://lichess.org/@/{}", "urlMain": "https://lichess.org", "errorType": "status_code",
                "presenceStrs": ["rating", "games"]},
    "Duolingo": {"url": "https://www.duolingo.com/profile/{}", "urlMain": "https://www.duolingo.com", "errorType": "status_code"},
    "Trello": {"url": "https://trello.com/{}", "urlMain": "https://trello.com", "errorType": "status_code"},
    "Notion": {"url": "https://notion.so/{}", "urlMain": "https://notion.so", "errorType": "status_code"},
    "Figma": {"url": "https://www.figma.com/@{}", "urlMain": "https://www.figma.com", "errorType": "status_code"},
    "Canva": {"url": "https://www.canva.com/p/{}/", "urlMain": "https://www.canva.com", "errorType": "status_code"},
    "Etsy": {"url": "https://www.etsy.com/shop/{}", "urlMain": "https://www.etsy.com", "errorType": "status_code"},
    "eBay": {"url": "https://www.ebay.com/usr/{}", "urlMain": "https://www.ebay.com", "errorType": "status_code"},
    "SlideShare": {"url": "https://www.slideshare.net/{}", "urlMain": "https://www.slideshare.net", "errorType": "status_code"},
    "Scribd": {"url": "https://www.scribd.com/{}", "urlMain": "https://www.scribd.com", "errorType": "status_code"},
    "Wattpad": {"url": "https://www.wattpad.com/user/{}", "urlMain": "https://www.wattpad.com", "errorType": "status_code"},
    "Archive.org": {"url": "https://archive.org/details/@{}", "urlMain": "https://archive.org", "errorType": "status_code"},
    "Bandcamp": {"url": "https://{}.bandcamp.com", "urlMain": "https://bandcamp.com", "errorType": "status_code"},
    "Mixcloud": {"url": "https://www.mixcloud.com/{}/", "urlMain": "https://www.mixcloud.com", "errorType": "status_code"},
    "ReverbNation": {"url": "https://www.reverbnation.com/{}", "urlMain": "https://www.reverbnation.com", "errorType": "status_code"},
    "500px": {"url": "https://500px.com/p/{}", "urlMain": "https://500px.com", "errorType": "status_code"},
    "Unsplash": {"url": "https://unsplash.com/@{}", "urlMain": "https://unsplash.com", "errorType": "status_code"},
    "Pexels": {"url": "https://www.pexels.com/@{}", "urlMain": "https://www.pexels.com", "errorType": "status_code"},
    "VSCO": {"url": "https://vsco.co/{}/gallery", "urlMain": "https://vsco.co", "errorType": "status_code"},
    "Giphy": {"url": "https://giphy.com/{}", "urlMain": "https://giphy.com", "errorType": "status_code"},
    "Hashnode": {"url": "https://hashnode.com/@{}", "urlMain": "https://hashnode.com", "errorType": "status_code"},
    "Dev.to": {"url": "https://dev.to/{}", "urlMain": "https://dev.to", "errorType": "status_code",
               "presenceStrs": ["post", "comment"]},
    "Codeberg": {"url": "https://codeberg.org/{}", "urlMain": "https://codeberg.org", "errorType": "status_code"},
    "HackerEarth": {"url": "https://www.hackerearth.com/@{}", "urlMain": "https://www.hackerearth.com", "errorType": "status_code"},
    "GeeksforGeeks": {"url": "https://auth.geeksforgeeks.org/user/{}", "urlMain": "https://www.geeksforgeeks.org", "errorType": "status_code"},
    "BugCrowd": {"url": "https://bugcrowd.com/{}", "urlMain": "https://bugcrowd.com", "errorType": "status_code"},
    "HackerOne": {"url": "https://hackerone.com/{}", "urlMain": "https://hackerone.com", "errorType": "status_code"},
    "Clubhouse": {"url": "https://www.clubhouse.com/@{}", "urlMain": "https://www.clubhouse.com", "errorType": "status_code"},
    "Linktree": {"url": "https://linktr.ee/{}", "urlMain": "https://linktr.ee", "errorType": "status_code"},
    "Cash App": {"url": "https://cash.app/${}", "urlMain": "https://cash.app", "errorType": "status_code"},
    "Venmo": {"url": "https://account.venmo.com/u/{}", "urlMain": "https://venmo.com", "errorType": "status_code"},
    "Flipboard": {"url": "https://flipboard.com/@{}", "urlMain": "https://flipboard.com", "errorType": "status_code"},
    "Disqus": {"url": "https://disqus.com/by/{}/", "urlMain": "https://disqus.com", "errorType": "status_code"},
    "OpenSea": {"url": "https://opensea.io/{}", "urlMain": "https://opensea.io", "errorType": "status_code"},
    "Rarible": {"url": "https://rarible.com/{}", "urlMain": "https://rarible.com", "errorType": "status_code"},
    "ArtStation": {"url": "https://www.artstation.com/{}", "urlMain": "https://www.artstation.com", "errorType": "status_code"},
    "Itch.io": {"url": "https://{}.itch.io", "urlMain": "https://itch.io", "errorType": "status_code"},
    "Newgrounds": {"url": "https://{}.newgrounds.com", "urlMain": "https://www.newgrounds.com", "errorType": "status_code"},
    "Kick": {"url": "https://kick.com/{}", "urlMain": "https://kick.com", "errorType": "status_code"},
    "Rumble": {"url": "https://rumble.com/user/{}", "urlMain": "https://rumble.com", "errorType": "status_code"},
    "BitChute": {"url": "https://www.bitchute.com/channel/{}/", "urlMain": "https://www.bitchute.com", "errorType": "status_code"},
    "Odysee": {"url": "https://odysee.com/@{}", "urlMain": "https://odysee.com", "errorType": "status_code"},
    "SourceForge": {"url": "https://sourceforge.net/u/{}/profile", "urlMain": "https://sourceforge.net", "errorType": "status_code"},
    "Launchpad": {"url": "https://launchpad.net/~{}", "urlMain": "https://launchpad.net", "errorType": "status_code"},
    "Codecademy": {"url": "https://www.codecademy.com/profiles/{}", "urlMain": "https://www.codecademy.com", "errorType": "status_code"},
    "FreeCodeCamp": {"url": "https://www.freecodecamp.org/{}", "urlMain": "https://www.freecodecamp.org", "errorType": "status_code"},
    "Exercism": {"url": "https://exercism.org/profiles/{}", "urlMain": "https://exercism.org", "errorType": "status_code"},
    "Strava": {"url": "https://www.strava.com/athletes/{}", "urlMain": "https://www.strava.com", "errorType": "status_code"},
    "Garmin Connect": {"url": "https://connect.garmin.com/modern/profile/{}", "urlMain": "https://connect.garmin.com", "errorType": "status_code"},
    "Letterboxd": {"url": "https://letterboxd.com/{}/", "urlMain": "https://letterboxd.com", "errorType": "status_code",
                   "presenceStrs": ["films", "reviews"]},
    "Trakt": {"url": "https://trakt.tv/users/{}", "urlMain": "https://trakt.tv", "errorType": "status_code"},
    "IMDb": {"url": "https://www.imdb.com/user/{}/", "urlMain": "https://www.imdb.com", "errorType": "status_code"},
    "AllTrails": {"url": "https://www.alltrails.com/members/{}", "urlMain": "https://www.alltrails.com", "errorType": "status_code"},
    "Instructables": {"url": "https://www.instructables.com/member/{}/", "urlMain": "https://www.instructables.com", "errorType": "status_code"},
    "Thingiverse": {"url": "https://www.thingiverse.com/{}", "urlMain": "https://www.thingiverse.com", "errorType": "status_code"},
    "F3": {"url": "https://f3.cool/{}/", "urlMain": "https://f3.cool", "errorType": "status_code"},
    "ShareChat": {"url": "https://sharechat.com/profile/{}", "urlMain": "https://sharechat.com", "errorType": "status_code",
                   "presenceStrs": ["Followers", "Following", "Posts"]},
    "Koo": {"url": "https://www.kooapp.com/profile/{}", "urlMain": "https://www.kooapp.com", "errorType": "status_code",
            "presenceStrs": ["Followers", "Following", "Koos"]},
    "Josh": {"url": "https://share.myjosh.in/profile/{}", "urlMain": "https://share.myjosh.in", "errorType": "status_code",
             "presenceStrs": ["Fans", "Following", "Videos"]},
    "Moj": {"url": "https://mojapp.in/@{}", "urlMain": "https://mojapp.in", "errorType": "status_code",
            "presenceStrs": ["Followers", "Following", "Likes"]},
    "Roposo": {"url": "https://www.roposo.com/profile/{}", "urlMain": "https://www.roposo.com", "errorType": "status_code",
               "presenceStrs": ["Followers", "Following"]},
    "Chingari": {"url": "https://chingari.io/{}", "urlMain": "https://chingari.io", "errorType": "status_code",
                 "presenceStrs": ["Followers", "Following", "Gari"]},
    "Naukri": {"url": "https://www.naukri.com/{}", "urlMain": "https://www.naukri.com", "errorType": "status_code",
               "presenceStrs": ["Work Experience", "Education"]},
    "Zomato": {"url": "https://www.zomato.com/users/{}", "urlMain": "https://www.zomato.com", "errorType": "status_code",
               "presenceStrs": ["Reviews", "Photos", "Followers"]},
    "Swiggy": {"url": "https://www.swiggy.com/profile/{}", "urlMain": "https://www.swiggy.com", "errorType": "status_code",
               "presenceStrs": ["Orders", "Reviews"]},
    "Paytm": {"url": "https://paytm.com/{}", "urlMain": "https://paytm.com", "errorType": "status_code"},
    "Snapdeal": {"url": "https://www.snapdeal.com/seller/{}", "urlMain": "https://www.snapdeal.com", "errorType": "status_code"},
    "BigBasket": {"url": "https://www.bigbasket.com/user/{}", "urlMain": "https://www.bigbasket.com", "errorType": "status_code"},
    "JioSaavn": {"url": "https://www.jiosaavn.com/user/{}", "urlMain": "https://www.jiosaavn.com", "errorType": "status_code",
                 "presenceStrs": ["Playlists", "Followers"]},
    "Gaana": {"url": "https://gaana.com/user/{}", "urlMain": "https://gaana.com", "errorType": "status_code"},
}


# ─── Helpers ───

def _generate_random_username(length=18):
    """Generate a guaranteed-nonexistent random username for calibration."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _replace_payload(obj, username):
    """Recursively replace {} in request payloads."""
    if isinstance(obj, str):
        return obj.replace("{}", username)
    if isinstance(obj, dict):
        return {k: _replace_payload(v, username) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_payload(item, username) for item in obj]
    return obj


def _ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if isinstance(value, tuple):
        return [str(item) for item in value if item not in (None, "")]
    if value == "":
        return []
    return [str(value)]


def _positive_markers(site_info):
    markers = []
    markers.extend(_ensure_list(site_info.get("presenceStrs")))
    markers.extend(_ensure_list(site_info.get("positiveStrings")))
    seen = set()
    ordered = []
    for marker in markers:
        marker = marker.strip()
        if not marker or marker in seen:
            continue
        seen.add(marker)
        ordered.append(marker)
    return ordered


def _negative_markers(site_info):
    markers = []
    markers.extend(_ensure_list(site_info.get("errorMsg")))
    markers.extend(_ensure_list(site_info.get("negativeStrings")))
    seen = set()
    ordered = []
    for marker in markers:
        marker = marker.strip()
        if not marker or marker in seen:
            continue
        seen.add(marker)
        ordered.append(marker)
    return ordered


def _status_codes(site_info, key):
    raw = site_info.get(key)
    codes = []
    for item in _ensure_list(raw):
        try:
            codes.append(int(item))
        except (TypeError, ValueError):
            continue
    return codes


def _contains_any_marker(body_text, markers):
    if not body_text or not markers:
        return False
    body_lower = body_text.lower()
    return any(marker.lower() in body_lower for marker in markers)


def _username_in_body(body_text, username):
    if not body_text or not username:
        return False
    lowered = body_text.lower()
    user = username.lower()
    if user not in lowered:
        return False

    escaped = re.escape(user)
    patterns = [
        rf'(?<![a-z0-9]){escaped}(?![a-z0-9])',
        rf'["\']{escaped}["\']',
        rf'@{escaped}(?![a-z0-9])',
        rf'/{escaped}(?:["\'/?#]|$)',
    ]
    for pattern in patterns:
        if re.search(pattern, lowered):
            return True
    return False


def _get_site_sample_username(site_info):
    claimed = str(site_info.get("username_claimed", "")).strip()
    if claimed:
        return claimed

    for item in _ensure_list(site_info.get("knownUsernames")):
        sample = item.strip()
        if sample:
            return sample

    return None


def _site_rule_strength(site_info):
    if _positive_markers(site_info):
        return "strong"
    if _negative_markers(site_info):
        return "medium"
    if site_info.get("errorType") == "response_url" and site_info.get("errorUrl"):
        return "medium"
    if _status_codes(site_info, "claimedStatusCodes") or _status_codes(site_info, "unclaimedStatusCodes"):
        return "medium"
    return "weak"


def _emit_log(logger, message, level="info", **fields):
    if not logger:
        return
    payload = {"level": level, "message": message}
    payload.update(fields)
    try:
        logger(payload)
    except Exception:
        pass


def _emit_progress(progress_cb, **fields):
    if not progress_cb:
        return
    try:
        progress_cb(fields)
    except Exception:
        pass


def _load_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_json_file(path, payload):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        return True
    except Exception:
        return False


def _detect_waf(text):
    """Check response text for WAF/bot-detection signatures (case-insensitive)."""
    if not text:
        return False
    text_lower = text[:5000].lower()
    for sig in WAF_SIGNATURES:
        if sig in text_lower:
            return True
    return False


def _check_username_format(username, site_name):
    """Validate username against site-specific format rules."""
    pattern = USERNAME_RULES.get(site_name)
    if pattern:
        try:
            return bool(re.match(pattern, username))
        except re.error:
            return True
    return True


def _make_request(url, headers, method="GET", json_payload=None, allow_redirects=True):
    """Make an HTTP request, returning (response, None) or (None, error_string)."""
    try:
        if method == "POST" and json_payload:
            resp = requests.post(url, headers=headers, json=json_payload,
                                 timeout=TIMEOUT, allow_redirects=allow_redirects)
        elif method == "PUT" and json_payload:
            resp = requests.put(url, headers=headers, json=json_payload,
                                timeout=TIMEOUT, allow_redirects=allow_redirects)
        elif method == "HEAD":
            resp = requests.head(url, headers=headers,
                                 timeout=TIMEOUT, allow_redirects=allow_redirects)
        else:
            resp = requests.get(url, headers=headers,
                                timeout=TIMEOUT, allow_redirects=allow_redirects)
        return resp, None
    except requests.exceptions.RequestException:
        return None, "request_failed"


def _build_probe_request(site_info, username):
    url_template = site_info.get("url", "")
    url_probe_template = site_info.get("urlProbe", url_template)
    error_type = site_info.get("errorType", "status_code")
    method = site_info.get("request_method") or "GET"
    method = method.upper()
    allow_redirects = error_type != "response_url"

    headers = dict(DEFAULT_HEADERS)
    if "headers" in site_info:
        headers.update(site_info["headers"])

    json_payload = None
    if "request_payload" in site_info:
        json_payload = _replace_payload(site_info["request_payload"], username)

    profile_url = url_template.replace("{}", username)
    probe_url = url_probe_template.replace("{}", quote(username))
    return profile_url, probe_url, headers, method, json_payload, allow_redirects


def _basic_claim_decision(resp, body_text, site_info, profile_url, probe_url):
    error_type = site_info.get("errorType", "status_code")
    status = resp.status_code

    positive_codes = set(_status_codes(site_info, "claimedStatusCodes"))
    negative_codes = set(_status_codes(site_info, "unclaimedStatusCodes"))
    legacy_error_codes = set(_status_codes(site_info, "errorCode"))
    positive_markers = _positive_markers(site_info)
    negative_markers = _negative_markers(site_info)
    final_url = resp.url if hasattr(resp, "url") else probe_url

    if error_type == "status_code":
        if _contains_any_marker(body_text, negative_markers):
            return False
        if status in negative_codes or status in legacy_error_codes:
            return False
        if positive_codes:
            return status in positive_codes
        return 200 <= status < 300

    if error_type == "message":
        if _contains_any_marker(body_text, negative_markers):
            return False
        if positive_markers:
            return _contains_any_marker(body_text, positive_markers)
        return 200 <= status < 300

    if error_type == "response_url":
        if not (200 <= status < 300):
            return False
        error_url = str(site_info.get("errorUrl", "")).strip()
        if error_url and final_url.rstrip("/") == error_url.rstrip("/"):
            return False
        expected_domain = urlparse(profile_url).netloc
        final_domain = urlparse(final_url).netloc
        return expected_domain == final_domain or expected_domain in final_domain

    return 200 <= status < 300


# ─── Site data loading ───

def load_sites():
    """Load site definitions from Sherlock + WhatsMyName (with caching and fallback)."""
    now = time.time()

    if _sites_cache["data"] and (now - _sites_cache["fetched_at"]) < CACHE_TTL:
        return _sites_cache["data"]

    # Primary: Sherlock data.json
    sherlock_sites = {}
    try:
        resp = requests.get(SHERLOCK_DATA_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        sherlock_sites = {k: v for k, v in data.items()
                         if not k.startswith("$") and isinstance(v, dict) and "url" in v}
        print(f"[OSINT] Loaded {len(sherlock_sites)} sites from Sherlock data.json")
    except Exception as e:
        print(f"[OSINT] Failed to fetch Sherlock data.json: {e}")

    # Supplementary: WhatsMyName wmn-data.json
    wmn_sites = _load_wmn_sites()

    # Merge: WMN supplements Sherlock, and both supplement FALLBACK_SITES
    merged = dict(FALLBACK_SITES)

    # Add/Update with Sherlock sites
    for name, info in sherlock_sites.items():
        if name not in merged:
            merged[name] = info
        else:
            merged[name].update(info)

    # Add/Update with WMN sites
    for name, info in wmn_sites.items():
        if name not in merged:
            merged[name] = info
        else:
            # Supplement existing definitions with WMN's stronger proof markers and samples.
            for key in (
                "presenceStrs",
                "positiveStrings",
                "negativeStrings",
                "claimedStatusCodes",
                "unclaimedStatusCodes",
                "knownUsernames",
                "urlProbe",
                "source",
            ):
                if not merged[name].get(key) and info.get(key):
                    merged[name][key] = info[key]

    if not merged:
        print(f"[OSINT] Using {len(FALLBACK_SITES)} bundled fallback sites")
        merged = dict(FALLBACK_SITES)

    _sites_cache["data"] = merged
    _sites_cache["fetched_at"] = now
    print(f"[OSINT] Total merged sites: {len(merged)}")
    return merged


def build_certified_site_manifest(force=False):
    """
    Build a lightweight runtime manifest that suppresses weak-rule sites before
    a scan begins. This manifest is definition-driven and safe to reuse across runs.
    """
    existing = None if force else _load_json_file(VALIDATED_SITES_PATH)
    raw_sites = load_sites()

    sites_payload = {}
    for site_name, site_info in raw_sites.items():
        rule_strength = _site_rule_strength(site_info)
        enabled = rule_strength != "weak"
        suppression_reason = None if enabled else "weak_rule_set"

        sites_payload[site_name] = {
            "enabled": enabled,
            "rule_strength": rule_strength,
            "source": site_info.get("source") or ("fallback" if site_name in FALLBACK_SITES else "merged"),
            "positive_marker_count": len(_positive_markers(site_info)),
            "negative_marker_count": len(_negative_markers(site_info)),
            "known_username_count": len(_ensure_list(site_info.get("knownUsernames"))),
            "suppression_reason": suppression_reason,
            "last_built_at": datetime.utcnow().isoformat() + "Z",
        }

        if existing and isinstance(existing.get("sites", {}).get(site_name), dict):
            prev = existing["sites"][site_name]
            if prev.get("validation"):
                sites_payload[site_name]["validation"] = prev["validation"]

    manifest = {
        "version": 1,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_sites": len(raw_sites),
        "enabled_sites": sum(1 for item in sites_payload.values() if item.get("enabled")),
        "sites": sites_payload,
    }
    _write_json_file(VALIDATED_SITES_PATH, manifest)
    return manifest


def load_certified_site_manifest(force_refresh=False):
    if force_refresh:
        return build_certified_site_manifest(force=True)

    manifest = _load_json_file(VALIDATED_SITES_PATH)
    if manifest and isinstance(manifest.get("sites"), dict):
        return manifest
    return build_certified_site_manifest(force=True)


def get_runtime_site_definitions(force_manifest_refresh=False, logger=None):
    raw_sites = load_sites()
    manifest = load_certified_site_manifest(force_refresh=force_manifest_refresh)
    enabled_sites = {}
    suppressed = 0

    manifest_sites = manifest.get("sites", {})
    for site_name, site_info in raw_sites.items():
        site_manifest = manifest_sites.get(site_name, {})
        if not site_manifest.get("enabled", True):
            suppressed += 1
            continue
        enabled_sites[site_name] = site_info

    _emit_log(
        logger,
        "Loaded certified site manifest",
        phase="manifest",
        total_sites=len(raw_sites),
        enabled_sites=len(enabled_sites),
        suppressed_sites=suppressed,
        manifest_path=VALIDATED_SITES_PATH,
    )
    return enabled_sites, manifest


# ─── Calibration (Maigret-style) ───

def _get_calibration(site_name, url_template, url_probe_template, headers, method, error_type, site_info):
    """
    Make a request with a random nonexistent username to establish a baseline
    response size and status code. Cached per site for CALIBRATION_TTL seconds.
    """
    now = time.time()
    cached = _calibration_cache.get(site_name)
    if cached and (now - cached["timestamp"]) < CALIBRATION_TTL:
        return cached

    random_user = _generate_random_username()
    profile_url = url_template.replace("{}", random_user)
    probe_url = url_probe_template.replace("{}", quote(random_user))

    allow_redirects = error_type != "response_url"
    json_payload = None
    if "request_payload" in site_info:
        json_payload = _replace_payload(site_info["request_payload"], random_user)

    resp, err = _make_request(probe_url, headers, method, json_payload, allow_redirects)
    if resp is None:
        return None

    body_text = ""
    if method != "HEAD" and hasattr(resp, 'text'):
        body_text = resp.text or ""

    positive_markers = _positive_markers(site_info)
    negative_markers = _negative_markers(site_info)
    looks_claimed = _basic_claim_decision(resp, body_text, site_info, profile_url, probe_url)
    positive_found = _contains_any_marker(body_text, positive_markers)
    negative_found = _contains_any_marker(body_text, negative_markers)
    username_found = _username_in_body(body_text, random_user)

    result = {
        "status": resp.status_code,
        "size": len(body_text),
        "skeleton": _compute_dom_skeleton(body_text) if body_text else [],
        "looks_claimed": looks_claimed,
        "positive_marker_found": positive_found,
        "negative_marker_found": negative_found,
        "username_found": username_found,
        "timestamp": now,
    }
    _calibration_cache[site_name] = result
    return result


def _validate_site_configuration(site_name, site_info, headers, method, error_type):
    now = time.time()
    cached = _site_validation_cache.get(site_name)
    if cached and (now - cached["timestamp"]) < SITE_VALIDATION_TTL:
        return cached

    url_template = site_info.get("url", "")
    url_probe_template = site_info.get("urlProbe", url_template)
    calibration = _get_calibration(site_name, url_template, url_probe_template, headers, method, error_type, site_info)
    rule_strength = _site_rule_strength(site_info)

    suppressed = False
    reasons = []

    if rule_strength == "weak":
        suppressed = True
        reasons.append("missing_direct_proof_rules")

    if calibration and calibration.get("looks_claimed") and not calibration.get("negative_marker_found"):
        suppressed = True
        reasons.append("unclaimed_probe_looked_claimed")

    sample_username = _get_site_sample_username(site_info)
    sample_verified = False
    should_verify_sample = site_name in STRICT_SITES or rule_strength != "strong"
    if sample_username and should_verify_sample and not suppressed:
        profile_url, probe_url, sample_headers, sample_method, json_payload, allow_redirects = _build_probe_request(site_info, sample_username)
        resp, err = _make_request(probe_url, sample_headers, sample_method, json_payload, allow_redirects)
        if resp is not None:
            sample_body = resp.text or "" if hasattr(resp, "text") else ""
            sample_verified = _basic_claim_decision(resp, sample_body, site_info, profile_url, probe_url)
            if not sample_verified:
                suppressed = True
                reasons.append("known_claimed_sample_failed")

    result = {
        "suppressed": suppressed,
        "reasons": reasons,
        "rule_strength": rule_strength,
        "sample_verified": sample_verified,
        "timestamp": now,
    }
    _site_validation_cache[site_name] = result
    return result


def _fast_probe_site(username, site_name, site_info, derived=False):
    """
    Cheap stage-A probe.
    Only performs request + basic claim logic + lightweight proof checks.
    Expensive validation, calibration, metadata extraction, and DOM work are deferred.
    """
    regex_check = site_info.get("regexCheck")
    if regex_check:
        try:
            if not re.match(regex_check, username):
                return {"site": site_name, "state": "skipped", "reason": "regex_mismatch"}
        except re.error:
            pass

    if not _check_username_format(username, site_name):
        return {"site": site_name, "state": "skipped", "reason": "username_format_invalid"}

    profile_url, probe_url, headers, method, json_payload, allow_redirects = _build_probe_request(site_info, username)
    started = time.time()
    resp, err = _make_request(probe_url, headers, method, json_payload, allow_redirects)
    if resp is None:
        return {"site": site_name, "state": "skipped", "reason": err or "request_failed"}

    body_text = ""
    if hasattr(resp, "text"):
        body_text = resp.text or ""

    if _detect_waf(body_text):
        return {"site": site_name, "state": "skipped", "reason": "waf_detected"}

    if not _basic_claim_decision(resp, body_text, site_info, profile_url, probe_url):
        return {
            "site": site_name,
            "state": "negative",
            "reason": "basic_claim_rejected",
            "http_status": resp.status_code,
            "response_time_ms": int((time.time() - started) * 1000),
        }

    positive_markers = _positive_markers(site_info)
    negative_markers = _negative_markers(site_info)
    presence_found = _contains_any_marker(body_text, positive_markers)
    username_found = _username_in_body(body_text, username)
    negative_found = _contains_any_marker(body_text, negative_markers)

    # A site becomes a candidate only if there is direct lightweight proof.
    if not presence_found and not username_found:
        return {
            "site": site_name,
            "state": "negative",
            "reason": "no_lightweight_proof",
            "http_status": resp.status_code,
            "response_time_ms": int((time.time() - started) * 1000),
        }

    return {
        "site": site_name,
        "state": "candidate",
        "site_info": site_info,
        "profile_url": profile_url,
        "probe_url": probe_url,
        "headers": headers,
        "method": method,
        "error_type": site_info.get("errorType", "status_code"),
        "username": username,
        "derived": derived,
        "body_text": body_text,
        "http_status": resp.status_code,
        "final_url": resp.url if hasattr(resp, "url") else probe_url,
        "response_time_ms": int((time.time() - started) * 1000),
        "presence_found": presence_found,
        "username_found": username_found,
        "negative_found": negative_found,
    }


def _verify_site_candidate(candidate):
    """
    Stage-B deep verification.
    Uses expensive validation and scoring only after a site is already a candidate.
    """
    site_name = candidate["site"]
    site_info = candidate["site_info"]
    username = candidate["username"]
    derived = candidate.get("derived", False)
    url_template = site_info.get("url", "")
    error_type = candidate["error_type"]
    body_text = candidate["body_text"]
    profile_url = candidate["profile_url"]
    probe_url = candidate["probe_url"]
    headers = candidate["headers"]
    method = candidate["method"]

    validation = _validate_site_configuration(site_name, site_info, headers, method, error_type)
    if validation.get("suppressed"):
        return None

    signals = {}
    positive_markers = _positive_markers(site_info)
    negative_markers = _negative_markers(site_info)
    positive_codes = set(_status_codes(site_info, "claimedStatusCodes"))

    signals["status_code_ok"] = candidate["http_status"] in positive_codes if positive_codes else 200 <= candidate["http_status"] < 300
    signals["no_waf"] = True

    if error_type != "response_url":
        expected_domain = urlparse(profile_url).netloc
        final_domain = urlparse(candidate["final_url"]).netloc
        signals["no_redirect"] = expected_domain == final_domain or expected_domain in final_domain
    else:
        signals["no_redirect"] = True

    absence_found = _contains_any_marker(body_text, negative_markers)
    signals["absence_string_missing"] = bool(negative_markers) and not absence_found
    signals["presence_string_found"] = candidate.get("presence_found", False) or _contains_any_marker(body_text, positive_markers)
    signals["username_in_content"] = candidate.get("username_found", False) or _username_in_body(body_text, username)

    is_strict = site_name in STRICT_SITES
    weak_rules = validation.get("rule_strength") == "weak"
    calib = _get_calibration(site_name, url_template, site_info.get("urlProbe", url_template), headers, method, error_type, site_info)

    if calib and len(body_text) > 0:
        calib_size = max(calib["size"], 1)
        size_ratio = len(body_text) / calib_size
        if 0.95 <= size_ratio <= 1.05:
            signals["size_differs_from_calibration"] = False
        elif 0.85 <= size_ratio <= 1.15:
            signals["size_differs_from_calibration"] = not is_strict
        else:
            signals["size_differs_from_calibration"] = True
    else:
        signals["size_differs_from_calibration"] = False

    metadata = _extract_metadata(body_text, site_name)
    signals["metadata_found"] = any(v for v in metadata.values())

    if calib and calib.get("skeleton"):
        sim = _dom_similarity(_compute_dom_skeleton(body_text), calib["skeleton"])
        signals["dom_hash_differs"] = sim < 0.90
    else:
        signals["dom_hash_differs"] = False

    penalties = {}
    if calib and len(body_text) > 0:
        calib_size = max(calib["size"], 1)
        size_ratio = len(body_text) / calib_size
        if 0.95 <= size_ratio <= 1.05:
            penalties["soft_404_match"] = 20
        if calib.get("looks_claimed") and not calib.get("negative_marker_found"):
            penalties["unclaimed_probe_looked_claimed"] = 25 if is_strict else 20

    if not signals["no_redirect"]:
        final_path = urlparse(candidate["final_url"]).path.lower()
        if any(p in final_path for p in ("/login", "/signin", "/register", "/home", "/404")):
            penalties["redirect_to_login"] = 15

    if weak_rules:
        penalties["weak_site_rules"] = 20

    direct_proof = signals["presence_string_found"] or (
        signals["username_in_content"] and (
            signals["size_differs_from_calibration"] or
            signals["dom_hash_differs"] or
            signals["metadata_found"]
        )
    )
    if not direct_proof:
        return None

    confidence, tier, gate_breakdown = _calculate_mlew_confidence(signals, penalties)
    threshold = CONFIDENCE_THRESHOLD
    if is_strict:
        threshold += 10
    if weak_rules:
        threshold += 10
    if derived:
        threshold += DERIVED_CONFIDENCE_BONUS
    if confidence < threshold or tier == "noise":
        return None
    if derived and tier not in REPORTABLE_TIERS:
        return None

    pivots = _extract_pivots_from_metadata(metadata, body_text)
    evidence = []
    if signals["presence_string_found"]:
        evidence.append("positive_marker")
    if signals["username_in_content"]:
        evidence.append("username_match")
    if signals["metadata_found"]:
        evidence.append("metadata")
    if signals["size_differs_from_calibration"]:
        evidence.append("size_delta")
    if signals["dom_hash_differs"]:
        evidence.append("dom_delta")

    return {
        "site": site_name,
        "url": profile_url,
        "url_main": site_info.get("urlMain", ""),
        "status": "FOUND",
        "http_status": candidate["http_status"],
        "response_time_ms": candidate["response_time_ms"],
        "confidence": confidence,
        "confidence_label": tier,
        "gate_breakdown": gate_breakdown,
        "metadata": metadata,
        "pivots": pivots,
        "evidence": evidence,
        "rule_strength": validation.get("rule_strength"),
        "derived": derived,
    }


# ─── Environment & External APIs ───

BREACH_API_BASE_URL = os.getenv("BREACH_API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

def _call_breach_api(path, payload=None):
    """Helper to query the unified search backend for identity correlation."""
    try:
        url = f"{BREACH_API_BASE_URL}{path}"
        resp = requests.post(url, json=payload or {}, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"[OSINT-Breach] API call failed: {e}")
    return None

# ─── Input type detection ───

def detect_input_type(input_str):
    """Auto-detect the type of OSINT input: EMAIL, PHONE, NAME, or USERNAME."""
    s = input_str.strip()
    if _EMAIL_RE.match(s):
        return "EMAIL"
    digits = re.sub(r'\D', '', s)
    if len(digits) >= 10 and len(digits) <= 15 and _PHONE_RE.match(s):
        return "PHONE"
    if ' ' in s and all(part.isalpha() for part in s.split() if part):
        return "NAME"
    return "USERNAME"


def _normalize_phone(phone_str):
    """Normalize phone number to last 10 digits."""
    digits = re.sub(r'\D', '', phone_str)
    if digits.startswith('91') and len(digits) > 10:
        digits = digits[2:]
    if digits.startswith('1') and len(digits) == 11:
        digits = digits[1:]
    if len(digits) > 10:
        digits = digits[-10:]
    return digits


def _derive_username_from_email(email):
    """Extract the local part of an email as a derived username."""
    local = email.split('@')[0].lower()
    local = re.sub(r'[._+-]+', '.', local).strip('.')
    return local


# ─── Metadata extraction ───

_OG_DESC_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:description["\']\s+content=["\']([^"\']{1,500})["\']',
    re.IGNORECASE
)
_META_DESC_RE = re.compile(
    r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']{1,500})["\']',
    re.IGNORECASE
)
_OG_IMAGE_RE = re.compile(
    r'<meta\s+property=["\']og:image["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE
)

SITE_METADATA_PATTERNS = {
    "GitHub": {
        "bio": r'<div[^>]*class="[^"]*user-profile-bio[^"]*"[^>]*>\s*<div[^>]*>(.*?)</div>',
        "location": r'<span[^>]*class="[^"]*p-label[^"]*"[^>]*>(.*?)</span>',
        "avatar": r'<img[^>]*class="[^"]*avatar[^"]*"[^>]*src="([^"]+)"',
    },
    "ShareChat": {
        "bio": r'<div[^>]*class="[^"]*profile-bio[^"]*"[^>]*>(.*?)</div>',
        "location": r'<span[^>]*class="[^"]*profile-location[^"]*"[^>]*>(.*?)</span>',
    },
    "Koo": {
        "bio": r'<div[^>]*class="[^"]*profile-description[^"]*"[^>]*>(.*?)</div>',
    },
    "Naukri": {
        "bio": r'<div[^>]*class="[^"]*jobSeekerProfile[^"]*"[^>]*>(.*?)</div>',
    },
    "Zomato": {
        "bio": r'<div[^>]*class="[^"]*profile-description[^"]*"[^>]*>(.*?)</div>',
    },
    "Reddit": {
        "bio": r'"public_description"\s*:\s*"([^"]{1,500})"',
    },
    "Steam": {
        "bio": r'<div\s+class="profile_summary"[^>]*>(.*?)</div>',
        "location": r'<div\s+class="header_real_name[^"]*"[^>]*>.*?<bdi>(.*?)</bdi>',
        "avatar": r'<div\s+class="playerAvatarAutoSizeInner"[^>]*>\s*<img\s+src="([^"]+)"',
    },
    "Twitter": {
        "bio": None,  # Twitter blocks scraping, rely on og:description
        "avatar": None,
    },
    "Dev.to": {
        "bio": r'<div[^>]*class="[^"]*profile-header__bio[^"]*"[^>]*>(.*?)</div>',
    },
    "Mastodon": {
        "bio": r'<div[^>]*class="[^"]*account__header__content[^"]*"[^>]*>(.*?)</div>',
    },
    "HackerNews": {
        "bio": r'<tr[^>]*>\s*<td[^>]*>about:</td>\s*<td[^>]*>(.*?)</td>',
    },
    "Keybase": {
        "bio": r'<p[^>]*class="[^"]*bio[^"]*"[^>]*>(.*?)</p>',
        "location": r'<p[^>]*class="[^"]*location[^"]*"[^>]*>(.*?)</p>',
    },
    "Medium": {
        "bio": None,  # Uses og:description
    },
    "Last.fm": {
        "bio": r'<span[^>]*class="[^"]*header-bio[^"]*"[^>]*>(.*?)</span>',
    },
    "Letterboxd": {
        "bio": r'<div[^>]*class="[^"]*body-text[^"]*"[^>]*>(.*?)</div>',
        "location": r'<div[^>]*class="[^"]*location[^"]*"[^>]*>(.*?)</div>',
    },
    "Behance": {
        "bio": None,
        "location": r'<span[^>]*class="[^"]*e2e-Profile-location[^"]*"[^>]*>(.*?)</span>',
    },
}

_LOCATION_PATTERNS = [
    re.compile(r'<[^>]*(?:class|itemprop)="[^"]*(?:location|addressLocality|p-label)[^"]*"[^>]*>(.*?)</', re.I),
]

_EMAIL_IN_TEXT_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}')
_AT_MENTION_RE = re.compile(r'(?:^|[\s(])@([a-zA-Z0-9_]{2,30})(?:[\s).,!?]|$)')


def _extract_metadata(body_text, site_name):
    """Extract bio, avatar URL, and location from HTML response via regex."""
    if not body_text:
        return {"bio": None, "location": None, "avatar_url": None}

    text_chunk = body_text[:30000]
    bio = None
    avatar_url = None
    location = None

    # Site-specific patterns first
    patterns = SITE_METADATA_PATTERNS.get(site_name, {})
    if patterns.get("bio"):
        try:
            m = re.search(patterns["bio"], text_chunk, re.DOTALL | re.IGNORECASE)
            if m:
                bio = _clean_html(m.group(1))
        except re.error:
            pass

    if patterns.get("avatar"):
        try:
            m = re.search(patterns["avatar"], text_chunk, re.IGNORECASE)
            if m:
                avatar_url = m.group(1)
        except re.error:
            pass

    if patterns.get("location"):
        try:
            m = re.search(patterns["location"], text_chunk, re.DOTALL | re.IGNORECASE)
            if m:
                location = _clean_html(m.group(1))
        except re.error:
            pass

    # Generic OpenGraph fallbacks
    if not bio:
        m = _OG_DESC_RE.search(text_chunk)
        if not m:
            m = _META_DESC_RE.search(text_chunk)
        if m:
            bio = html_module.unescape(m.group(1)).strip()

    if not avatar_url:
        m = _OG_IMAGE_RE.search(text_chunk)
        if m:
            avatar_url = m.group(1)

    if not location:
        for pat in _LOCATION_PATTERNS:
            m = pat.search(text_chunk)
            if m:
                location = _clean_html(m.group(1))
                break

    # Truncate
    if bio and len(bio) > 300:
        bio = bio[:297] + "..."
    if location and len(location) > 100:
        location = location[:100]

    return {"bio": bio, "location": location, "avatar_url": avatar_url}


def _clean_html(text):
    """Strip HTML tags and unescape entities."""
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html_module.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text if text else None


# ─── Pivot extraction ───

def _extract_pivots_from_metadata(metadata, body_text):
    """Extract potential pivot identifiers (emails, @mentions) from profile content."""
    pivots = []
    seen = set()

    bio = metadata.get("bio") or ""

    # Extract emails from bio
    for email in _EMAIL_IN_TEXT_RE.findall(bio):
        email_lower = email.lower()
        if email_lower not in seen:
            seen.add(email_lower)
            pivots.append({"type": "EMAIL", "value": email_lower})

    # Extract @mentions from bio
    for mention in _AT_MENTION_RE.findall(bio):
        mention_lower = mention.lower()
        if mention_lower not in seen:
            seen.add(mention_lower)
            pivots.append({"type": "USERNAME", "value": mention_lower})

    # Also scan first 10KB of body for emails (not mentions — too noisy)
    if body_text:
        for email in _EMAIL_IN_TEXT_RE.findall(body_text[:10000]):
            email_lower = email.lower()
            # Skip common false-positive domains
            if any(email_lower.endswith(d) for d in
                   ('@example.com', '@sentry.io', '@facebook.com', '@github.com',
                    '@twitter.com', '@google.com', '@w3.org', '@schema.org')):
                continue
            if email_lower not in seen:
                seen.add(email_lower)
                pivots.append({"type": "EMAIL", "value": email_lower})

    return pivots[:10]  # Cap at 10 pivots


# ─── DOM hashing (false positive reduction) ───

_TAG_RE = re.compile(r'<([a-zA-Z][a-zA-Z0-9]*)[^>]*>')


def _compute_dom_skeleton(html_text):
    """Extract ordered tag names from first 10KB of HTML."""
    return _TAG_RE.findall(html_text[:10000])


def _dom_similarity(skeleton_a, skeleton_b):
    """Compute Jaccard similarity of tag frequency vectors."""
    if not skeleton_a or not skeleton_b:
        return 0.0
    freq_a = Counter(skeleton_a)
    freq_b = Counter(skeleton_b)
    all_tags = set(freq_a) | set(freq_b)
    intersection = sum(min(freq_a.get(t, 0), freq_b.get(t, 0)) for t in all_tags)
    union = sum(max(freq_a.get(t, 0), freq_b.get(t, 0)) for t in all_tags)
    return intersection / union if union > 0 else 0.0


# ─── MLEW 4-Gate Confidence Scoring ───

def _calculate_mlew_confidence(signals, penalties=None):
    """
    Calculate confidence using the MLEW 4-gate scoring system.

    Returns (score 0-100, tier label, gate_breakdown dict).
    """
    # Gate 1: Technical Signal (20 pts max)
    gate1_weights = {
        "status_code_ok": 10,
        "no_waf": 5,
        "no_redirect": 5,
    }

    # Gate 2: Content Proof (40 pts max)
    gate2_weights = {
        "presence_string_found": 15,
        "absence_string_missing": 10,
        "username_in_content": 15,
    }

    # Gate 3: Identity Correlation (30 pts max)
    gate3_weights = {
        "size_differs_from_calibration": 15,
        "metadata_found": 10,
        "dom_hash_differs": 5,
    }

    def _score_gate(weights, sigs):
        earned = 0
        max_pts = 0
        details = {}
        for signal, pts in weights.items():
            max_pts += pts
            passed = sigs.get(signal, False)
            if passed:
                earned += pts
            details[signal] = {"passed": passed, "weight": pts}
        return earned, max_pts, details

    g1_score, g1_max, g1_details = _score_gate(gate1_weights, signals)
    g2_score, g2_max, g2_details = _score_gate(gate2_weights, signals)
    g3_score, g3_max, g3_details = _score_gate(gate3_weights, signals)

    raw_score = g1_score + g2_score + g3_score
    max_possible = g1_max + g2_max + g3_max  # 90

    # Gate 4: Negative Evidence (penalties)
    penalty_total = 0
    penalty_items = []
    if penalties:
        for reason, amount in penalties.items():
            penalty_total += abs(amount)
            penalty_items.append({"reason": reason, "penalty": -abs(amount)})

    # Normalize to 0-100, apply penalties
    score = round(raw_score / max_possible * 100) if max_possible > 0 else 50
    score = max(0, score - penalty_total)

    # Determine tier
    if score >= 90:
        tier = "verified"
    elif score >= 70:
        tier = "high"
    elif score >= 40:
        tier = "potential"
    else:
        tier = "noise"

    gate_breakdown = {
        "technical": {"score": g1_score, "max": g1_max, "signals": g1_details},
        "content": {"score": g2_score, "max": g2_max, "signals": g2_details},
        "correlation": {"score": g3_score, "max": g3_max, "signals": g3_details},
        "penalties": {"total": -penalty_total, "items": penalty_items},
    }

    return score, tier, gate_breakdown


# ─── Core site checker ───

def check_site(username, site_name, site_info, derived=False):
    """
    Check if a username exists on a single site with MLEW 4-gate validation.
    Returns a result dict with confidence score and metadata, or None if not found.
    """
    url_template = site_info.get("url", "")
    error_type = site_info.get("errorType", "status_code")
    url_main = site_info.get("urlMain", "")

    # Step 1: Username format pre-validation
    regex_check = site_info.get("regexCheck")
    if regex_check:
        try:
            if not re.match(regex_check, username):
                return None
        except re.error:
            pass

    if not _check_username_format(username, site_name):
        return None

    profile_url, probe_url, headers, method, json_payload, allow_redirects = _build_probe_request(site_info, username)

    validation = _validate_site_configuration(site_name, site_info, headers, method, error_type)
    if validation.get("suppressed"):
        return None

    # Step 2: Make the actual request
    resp, err = _make_request(probe_url, headers, method, json_payload, allow_redirects)
    if resp is None:
        return None

    body_text = ""
    if hasattr(resp, 'text'):
        body_text = resp.text or ""

    # Step 3: WAF detection
    is_waf = _detect_waf(body_text)
    if is_waf:
        return None

    # Step 4: Basic claim status (Sherlock-style)
    claimed = _basic_claim_decision(resp, body_text, site_info, profile_url, probe_url)
    if not claimed:
        return None

    # Step 5: Multi-signal validation (MLEW Gates 1-3)
    signals = {}
    positive_markers = _positive_markers(site_info)
    negative_markers = _negative_markers(site_info)
    positive_codes = set(_status_codes(site_info, "claimedStatusCodes"))

    # Gate 1: Technical signals
    signals["status_code_ok"] = resp.status_code in positive_codes if positive_codes else 200 <= resp.status_code < 300
    signals["no_waf"] = not is_waf

    # Redirect detection
    if error_type != "response_url":
        final_url = resp.url if hasattr(resp, 'url') else probe_url
        expected_domain = urlparse(profile_url).netloc
        final_domain = urlparse(final_url).netloc
        signals["no_redirect"] = expected_domain == final_domain or expected_domain in final_domain
    else:
        signals["no_redirect"] = True

    # Gate 2: Content proof
    absence_found = _contains_any_marker(body_text, negative_markers)
    signals["absence_string_missing"] = bool(negative_markers) and not absence_found

    signals["presence_string_found"] = _contains_any_marker(body_text, positive_markers)
    signals["username_in_content"] = _username_in_body(body_text, username)

    # Gate 3: Identity correlation
    is_strict = site_name in STRICT_SITES
    weak_rules = validation.get("rule_strength") == "weak"
    calib = _get_calibration(site_name, url_template, site_info.get("urlProbe", url_template),
                             headers, method, error_type, site_info)

    # Size comparison
    if calib and len(body_text) > 0:
        calib_size = max(calib["size"], 1)
        target_size = len(body_text)
        size_ratio = target_size / calib_size

        if 0.95 <= size_ratio <= 1.05:
            signals["size_differs_from_calibration"] = False
        elif 0.85 <= size_ratio <= 1.15:
            signals["size_differs_from_calibration"] = not is_strict
        else:
            signals["size_differs_from_calibration"] = True
    else:
        signals["size_differs_from_calibration"] = False

    # Metadata extraction
    metadata = _extract_metadata(body_text, site_name)
    signals["metadata_found"] = any(v for v in metadata.values())

    # DOM hashing (compare structure with calibration)
    if calib and calib.get("skeleton"):
        target_skeleton = _compute_dom_skeleton(body_text)
        sim = _dom_similarity(target_skeleton, calib["skeleton"])
        signals["dom_hash_differs"] = sim < 0.90
    else:
        signals["dom_hash_differs"] = False

    # Gate 4: Penalties
    penalties = {}
    if calib and len(body_text) > 0:
        calib_size = max(calib["size"], 1)
        size_ratio = len(body_text) / calib_size
        if 0.95 <= size_ratio <= 1.05:
            penalties["soft_404_match"] = 20
        if calib.get("looks_claimed") and not calib.get("negative_marker_found"):
            penalties["unclaimed_probe_looked_claimed"] = 25 if is_strict else 20

    if not signals["no_redirect"]:
        final_path = urlparse(resp.url if hasattr(resp, 'url') else probe_url).path.lower()
        if any(p in final_path for p in ('/login', '/signin', '/register', '/home', '/404')):
            penalties["redirect_to_login"] = 15

    if weak_rules:
        penalties["weak_site_rules"] = 20

    direct_proof = signals["presence_string_found"] or (
        signals["username_in_content"] and (
            signals["size_differs_from_calibration"] or
            signals["dom_hash_differs"] or
            signals["metadata_found"]
        )
    )

    if not direct_proof:
        return None

    # Step 6: MLEW confidence scoring
    confidence, tier, gate_breakdown = _calculate_mlew_confidence(signals, penalties)

    threshold = CONFIDENCE_THRESHOLD
    if is_strict:
        threshold += 10
    if weak_rules:
        threshold += 10
    if derived:
        threshold += DERIVED_CONFIDENCE_BONUS

    if confidence < threshold or tier == "noise":
        return None

    if derived and tier not in REPORTABLE_TIERS:
        return None

    # Extract pivots for potential recursive search
    pivots = _extract_pivots_from_metadata(metadata, body_text)

    evidence = []
    if signals["presence_string_found"]:
        evidence.append("positive_marker")
    if signals["username_in_content"]:
        evidence.append("username_match")
    if signals["metadata_found"]:
        evidence.append("metadata")
    if signals["size_differs_from_calibration"]:
        evidence.append("size_delta")
    if signals["dom_hash_differs"]:
        evidence.append("dom_delta")

    return {
        "site": site_name,
        "url": profile_url,
        "url_main": url_main,
        "status": "FOUND",
        "http_status": resp.status_code,
        "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
        "confidence": confidence,
        "confidence_label": tier,
        "gate_breakdown": gate_breakdown,
        "metadata": metadata,
        "pivots": pivots,
        "evidence": evidence,
        "rule_strength": validation.get("rule_strength"),
        "derived": derived,
    }


# ─── Site data loading ─── (WhatsMyName integration)

def _load_wmn_sites():
    """Load WhatsMyName data and convert to Sherlock-compatible format."""
    now = time.time()

    if _wmn_cache["data"] and (now - _wmn_cache["fetched_at"]) < CACHE_TTL:
        return _wmn_cache["data"]

    try:
        resp = requests.get(WMN_DATA_URL, timeout=15)
        resp.raise_for_status()
        raw = resp.json()
        websites = raw.get("sites", [])

        sites = {}
        for site in websites:
            name = site.get("name", "")
            uri = site.get("uri_check", "")
            if not name or not uri:
                continue

            # Convert WMN format to Sherlock-compatible
            uri_template = uri.replace("{account}", "{}")
            # uri_pretty is the human-readable profile page;
            # uri_check (uri_template) is the API probe endpoint
            uri_pretty = site.get("uri_pretty", "")
            if uri_pretty:
                profile_url = uri_pretty.replace("{account}", "{}")
            else:
                profile_url = uri_template
            info = {
                "url": profile_url,
                "urlProbe": uri_template,
                "urlMain": site.get("uri_main", ""),
                "errorType": "status_code",
                "source": "whatsmyname",
            }

            headers = site.get("headers")
            if isinstance(headers, dict) and headers:
                info["headers"] = headers

            post_body = site.get("post_body")
            if post_body:
                info["request_method"] = "POST"
                try:
                    info["request_payload"] = json.loads(post_body.replace("{account}", "{}"))
                except json.JSONDecodeError:
                    info["request_payload"] = post_body.replace("{account}", "{}")

            # Preserve WMN's explicit positive/negative evidence instead of inverting it.
            e_code = site.get("e_code")
            if e_code:
                info["claimedStatusCodes"] = e_code if isinstance(e_code, list) else [e_code]

            e_string = site.get("e_string")
            if e_string:
                info["positiveStrings"] = e_string if isinstance(e_string, list) else [e_string]

            m_code = site.get("m_code")
            if m_code:
                info["unclaimedStatusCodes"] = m_code if isinstance(m_code, list) else [m_code]

            m_string = site.get("m_string")
            if m_string:
                info["negativeStrings"] = m_string if isinstance(m_string, list) else [m_string]

            known = site.get("known", [])
            if known:
                info["knownUsernames"] = known if isinstance(known, list) else [known]

            sites[name] = info

        _wmn_cache["data"] = sites
        _wmn_cache["fetched_at"] = now
        print(f"[OSINT] Loaded {len(sites)} sites from WhatsMyName wmn-data.json")
        return sites
    except Exception as e:
        print(f"[OSINT] Failed to fetch WhatsMyName data: {e}")
        if _wmn_cache["data"]:
            return _wmn_cache["data"]
        return {}


# ─── Indian Priority Platforms ───

PRIORITY_INDIAN_SITES = {
    "Swiggy", "Zomato", "Naukri", "ShareChat", "Koo", "Josh", "Moj",
    "Roposo", "Chingari", "IndiaMart", "JustDial", "Mobikwik", "PhonePe",
    "Paytm", "BigBasket", "NaukriGulf", "FirstCry", "Netmeds", "Gaana",
    "JioSaavn", "Snapdeal", "Flipkart", "Myntra", "Ajio", "Licious",
    "Dunzo", "Ola", "Uber India", "MakeMyTrip", "ClearTrip", "BookMyShow",
}

# ─── Public API ───

def search_username(username, derived=False, logger=None, progress_cb=None, force_manifest_refresh=False):
    """
    Search a username across all certified sites with a staged pipeline:
    1. cheap candidate probe
    2. deep verification only for candidates
    """
    start_time = time.time()
    sites, manifest = get_runtime_site_definitions(force_manifest_refresh=force_manifest_refresh, logger=logger)
    found = []
    candidates = []

    # Separate priority sites from general sites
    priority_list = []
    general_list = []
    for name, info in sites.items():
        if name in PRIORITY_INDIAN_SITES:
            priority_list.append((name, info))
        else:
            general_list.append((name, info))

    # Recombine with priority first
    ordered_sites = priority_list + general_list
    total_sites = len(ordered_sites)
    scanned_sites = 0
    verified_sites = 0
    potential_sites = 0

    _emit_progress(
        progress_cb,
        phase="candidate_scan",
        sites_total=total_sites,
        sites_scanned=0,
        candidates_found=0,
        verified_found=0,
        potential_found=0,
    )
    _emit_log(logger, "Starting candidate scan", phase="candidate_scan", username=username, total_sites=total_sites, derived=derived)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for site_name, site_info in ordered_sites:
            _emit_log(logger, "Scanning site", phase="candidate_scan", site=site_name)
            f = executor.submit(_fast_probe_site, username, site_name, site_info, derived)
            futures[f] = site_name

        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                scanned_sites += 1
                _emit_log(logger, "Candidate scan failed", level="error", phase="candidate_scan", site=futures[future], error=str(exc))
                _emit_progress(progress_cb, phase="candidate_scan", sites_total=total_sites, sites_scanned=scanned_sites, candidates_found=len(candidates), verified_found=verified_sites, potential_found=potential_sites)
                continue

            scanned_sites += 1
            state = result.get("state")
            if state == "candidate":
                candidates.append(result)
                _emit_log(logger, "Candidate promoted", phase="candidate_scan", site=result["site"], http_status=result.get("http_status"), response_time_ms=result.get("response_time_ms"))
            else:
                _emit_log(logger, "Site rejected in candidate scan", phase="candidate_scan", site=result.get("site"), reason=result.get("reason"), http_status=result.get("http_status"))

            _emit_progress(
                progress_cb,
                phase="candidate_scan",
                sites_total=total_sites,
                sites_scanned=scanned_sites,
                candidates_found=len(candidates),
                verified_found=verified_sites,
                potential_found=potential_sites,
            )

    _emit_log(logger, "Candidate scan completed", phase="candidate_scan", candidates_found=len(candidates), scanned_sites=scanned_sites)
    _emit_progress(progress_cb, phase="verification", sites_total=total_sites, sites_scanned=scanned_sites, candidates_found=len(candidates), verified_found=verified_sites, potential_found=potential_sites)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for candidate in candidates:
            _emit_log(logger, "Verifying candidate", phase="verification", site=candidate["site"])
            futures[executor.submit(_verify_site_candidate, candidate)] = candidate["site"]

        for future in as_completed(futures):
            site_name = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                _emit_log(logger, "Verification failed", level="error", phase="verification", site=site_name, error=str(exc))
                continue

            if result:
                found.append(result)
                if result.get("confidence_label") == "potential":
                    potential_sites += 1
                    _emit_log(logger, "Potential match retained", phase="verification", site=site_name, confidence=result.get("confidence"))
                else:
                    verified_sites += 1
                    _emit_log(logger, "Verified/high match accepted", phase="verification", site=site_name, confidence=result.get("confidence"), tier=result.get("confidence_label"))
            else:
                _emit_log(logger, "Candidate rejected after deep verification", phase="verification", site=site_name)

            _emit_progress(
                progress_cb,
                phase="verification",
                sites_total=total_sites,
                sites_scanned=scanned_sites,
                candidates_found=len(candidates),
                verified_found=verified_sites,
                potential_found=potential_sites,
            )

    # Sort by confidence (highest first), then by site name
    found.sort(key=lambda x: (-x.get("confidence", 0), x["site"].lower()))
    reportable_found = [item for item in found if item.get("confidence_label") in REPORTABLE_TIERS]
    potential_found = [item for item in found if item.get("confidence_label") == "potential"]

    elapsed = (time.time() - start_time) * 1000

    return {
        "username": username,
        "found": reportable_found,
        "potential_found": potential_found,
        "total_checked": total_sites,
        "total_found": len(reportable_found),
        "potential_found_count": len(potential_found),
        "total_detected": len(found),
        "candidate_count": len(candidates),
        "manifest_path": VALIDATED_SITES_PATH,
        "search_time_ms": round(elapsed, 2),
    }


def search_csv_sources(target, input_type="USERNAME"):
    """Delegate to the single canonical CSV-search implementation."""
    from modules.osint.osint_engine.csv_search import search_csv_sources as search

    return search(target, input_type)


def name_to_identity_correlation(name, logger=None):
    """
    Query the breach database to find emails or usernames associated with a name.
    This allows pivoting from NAME -> EMAIL/USERNAME.
    """
    payload = {
        "seed": name,
        "seed_type": "name",
        "max_depth": 1,
        "max_results_per_query": 50
    }

    _emit_log(logger, "Running breach correlation for name", phase="name_correlation", target=name)
    correlations = _call_breach_api("/search/correlation", payload)
    identities = {"emails": set(), "usernames": set()}

    if correlations and isinstance(correlations, list):
        for entity in correlations:
            emails = entity.get("emails", [])
            for email in emails:
                if email: identities["emails"].add(email.lower())

            # Extract potential usernames from records
            records = entity.get("raw_records", [])
            for rec in records:
                for field in ["fb_username", "ig_username", "linkedin_username", "twitter_handle", "bb_username", "naukri_username", "base_username"]:
                    val = rec.get(field)
                    if val and isinstance(val, str):
                        identities["usernames"].add(val.lower())

    result = {
        "emails": sorted(list(identities["emails"])),
        "usernames": sorted(list(identities["usernames"]))
    }
    _emit_log(logger, "Name correlation completed", phase="name_correlation", emails=len(result["emails"]), usernames=len(result["usernames"]))
    return result


def search_name_web(name, logger=None, progress_cb=None):
    """
    Comprehensive web enumeration for a name by pivoting through breach data.
    Returns correlated identities and their discovered social footprints.
    """
    start_time = time.time()

    # Step 1: Breach Correlation (Find linked emails/usernames)
    identities = name_to_identity_correlation(name, logger=logger)

    all_results = []
    visited_usernames = set()

    # Step 2: Search discovered usernames
    for username in identities["usernames"][:5]: # Cap at 5 usernames
        if username not in visited_usernames:
            visited_usernames.add(username)
            _emit_log(logger, "Searching correlated username", phase="name_web", pivot=username)
            res = search_username(username, derived=True, logger=logger, progress_cb=progress_cb)
            if res.get("found"):
                all_results.append(res)

    # Step 3: Search usernames derived from emails
    for email in identities["emails"][:3]: # Cap at 3 emails
        derived = _derive_username_from_email(email)
        if derived not in visited_usernames:
            visited_usernames.add(derived)
            _emit_log(logger, "Searching username derived from correlated email", phase="name_web", pivot=derived)
            res = search_username(derived, derived=True, logger=logger, progress_cb=progress_cb)
            if res.get("found"):
                all_results.append(res)

    elapsed = (time.time() - start_time) * 1000

    return {
        "name": name,
        "identities_found": identities,
        "social_footprint": all_results,
        "search_time_ms": round(elapsed, 2),
    }

def full_osint_search(target, logger=None, progress_cb=None):
    """
    Combined OSINT search with auto-input detection.
    Routes to appropriate strategy based on input type.
    """
    input_type = detect_input_type(target)
    start_time = time.time()

    web_results = None
    username_to_search = None
    derived_username = False
    name_results = None

    if input_type == "USERNAME":
        username_to_search = target
    elif input_type == "EMAIL":
        username_to_search = _derive_username_from_email(target)
        derived_username = True
    elif input_type == "NAME":
        _emit_log(logger, "Detected name input; switching to correlation-first search", phase="routing", target=target)
        name_results = search_name_web(target, logger=logger, progress_cb=progress_cb)
    # PHONE: no web enumeration, CSV-only

    # Run web enumeration for USERNAME and EMAIL
    if username_to_search:
        _emit_log(logger, "Starting username search", phase="routing", target=username_to_search, derived=derived_username)
        web_results = search_username(username_to_search, derived=derived_username, logger=logger, progress_cb=progress_cb)
    elif name_results:
        # For NAME, we use the results from search_name_web as the primary results
        web_results = {
            "username": target,
            "found": [],
            "potential_found": [],
            "identities": name_results.get("identities_found"),
            "social_footprint": name_results.get("social_footprint"),
            "total_checked": 0,
            "total_found": sum(r.get("total_found", 0) for r in name_results.get("social_footprint", [])),
            "potential_found_count": sum(r.get("potential_found_count", 0) for r in name_results.get("social_footprint", [])),
            "total_detected": sum(r.get("total_detected", 0) for r in name_results.get("social_footprint", [])),
            "search_time_ms": name_results.get("search_time_ms", 0),
        }
    else:
        web_results = {
            "username": target,
            "found": [],
            "potential_found": [],
            "total_checked": 0,
            "total_found": 0,
            "potential_found_count": 0,
            "total_detected": 0,
            "search_time_ms": 0,
        }

    # CSV cross-reference with appropriate input type
    csv_results = search_csv_sources(target, input_type)

    csv_by_source = {}
    for record in csv_results:
        src = record.pop("_source_csv", "unknown")
        field = record.pop("_matched_field", "unknown")
        if src not in csv_by_source:
            csv_by_source[src] = {"source": src, "matched_field": field, "records": []}
        csv_by_source[src]["records"].append(record)

    web_results["csv_matches"] = list(csv_by_source.values())
    web_results["csv_total"] = len(csv_results)
    web_results["input_type"] = input_type

    # For EMAIL, also note the derived username
    if input_type == "EMAIL" and username_to_search:
        web_results["derived_username"] = username_to_search
        web_results["derived_username_search"] = True

    # Total elapsed time
    elapsed = (time.time() - start_time) * 1000
    web_results["search_time_ms"] = round(elapsed, 2)

    _emit_log(logger, "OSINT search completed", phase="complete", input_type=input_type, total_found=web_results.get("total_found", 0), potential_found=web_results.get("potential_found_count", 0), search_time_ms=web_results.get("search_time_ms"))
    return web_results


# ─── Recursive OSINT Search ───

def _build_osint_graph(seed, seed_type, search_results, pivots_data):
    """Build a D3-compatible node/edge graph from OSINT results."""
    nodes = []
    edges = []
    node_ids = set()

    def _node_id(ntype, value):
        raw = f"{ntype.upper()}:{value.strip().lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    # Seed node
    seed_id = _node_id(seed_type, seed)
    nodes.append({
        "id": seed_id,
        "type": seed_type,
        "label": seed,
        "value": seed,
        "degree": 0,
        "is_seed": True,
    })
    node_ids.add(seed_id)

    # For NAME search, add Identity nodes (Emails/Usernames)
    identities = search_results.get("identities", {})
    for email in identities.get("emails", []):
        email_id = _node_id("EMAIL", email)
        if email_id not in node_ids:
            nodes.append({"id": email_id, "type": "EMAIL", "label": email, "value": email, "degree": 1, "is_seed": False})
            node_ids.add(email_id)
        edges.append({"source": seed_id, "target": email_id, "relationship": "IDENTITY_EMAIL"})

    for uname in identities.get("usernames", []):
        uname_id = _node_id("USERNAME", uname)
        if uname_id not in node_ids:
            nodes.append({"id": uname_id, "type": "USERNAME", "label": uname, "value": uname, "degree": 1, "is_seed": False})
            node_ids.add(uname_id)
        edges.append({"source": seed_id, "target": uname_id, "relationship": "IDENTITY_USERNAME"})

    # Site nodes from depth 0 results (Standard)
    depth_0_found = search_results.get("found", [])

    # Also add site nodes from social footprint for NAME search
    for footprint in search_results.get("social_footprint", []):
        depth_0_found.extend(footprint.get("found", []))
        # Find the node for the username/email that generated this footprint
        fp_uname = footprint.get("username")
        fp_type = footprint.get("input_type", "USERNAME")
        fp_source_id = _node_id(fp_type, fp_uname)

        for site in footprint.get("found", []):
            site_id = _node_id("SITE", site["url"])
            if site_id not in node_ids:
                nodes.append({
                    "id": site_id, "type": "SITE", "label": site["site"], "value": site["url"],
                    "degree": 2, "is_seed": False, "confidence": site.get("confidence"), "metadata": site.get("metadata"),
                })
                node_ids.add(site_id)
            if fp_source_id in node_ids:
                edges.append({"source": fp_source_id, "target": site_id, "relationship": "FOUND_ON"})

    for site in search_results.get("found", []):
        site_id = _node_id("SITE", site["url"])
        if site_id not in node_ids:
            nodes.append({
                "id": site_id,
                "type": "SITE",
                "label": site["site"],
                "value": site["url"],
                "degree": 1,
                "is_seed": False,
                "confidence": site.get("confidence"),
                "metadata": site.get("metadata"),
            })
            node_ids.add(site_id)
        edges.append({
            "source": seed_id,
            "target": site_id,
            "relationship": "FOUND_ON",
        })

    # Pivot nodes and their results
    for pivot_info in pivots_data:
        pivot_val = pivot_info["pivot_value"]
        pivot_type = pivot_info["pivot_type"]
        pivot_id = _node_id(pivot_type, pivot_val)

        if pivot_id not in node_ids:
            nodes.append({
                "id": pivot_id,
                "type": pivot_type,
                "label": pivot_val,
                "value": pivot_val,
                "degree": pivot_info.get("depth", 1),
                "is_seed": False,
            })
            node_ids.add(pivot_id)

        # Edge from source site to pivot
        source_site = pivot_info.get("source_site", "")
        source_site_id = _node_id("SITE", source_site) if source_site else seed_id
        if source_site_id in node_ids:
            edges.append({
                "source": source_site_id,
                "target": pivot_id,
                "relationship": "PIVOTED_TO",
            })

        # Site nodes from pivot results
        pivot_results = pivot_info.get("results", {})
        for site in pivot_results.get("found", []):
            site_id = _node_id("SITE", site["url"])
            if site_id not in node_ids:
                nodes.append({
                    "id": site_id,
                    "type": "SITE",
                    "label": site["site"],
                    "value": site["url"],
                    "degree": pivot_info.get("depth", 1) + 1,
                    "is_seed": False,
                    "confidence": site.get("confidence"),
                    "metadata": site.get("metadata"),
                })
                node_ids.add(site_id)
            edges.append({
                "source": pivot_id,
                "target": site_id,
                "relationship": "FOUND_ON",
            })

    return {"nodes": nodes, "edges": edges}


def recursive_osint_search(target, max_depth=2, logger=None, progress_cb=None):
    """
    BFS-style recursive OSINT search with automatic pivoting.
    Discovers new identifiers from profile metadata and expands the search.
    """
    input_type = detect_input_type(target)
    start_time = time.time()

    # Depth 0: initial search
    _emit_log(logger, "Starting recursive OSINT search", phase="recursive", target=target, max_depth=max_depth)
    depth_0 = full_osint_search(target, logger=logger, progress_cb=progress_cb)

    # For NAME search, 'found' might be empty, but 'social_footprint' has the results
    initial_found = depth_0.get("found", [])
    if not initial_found and depth_0.get("social_footprint"):
        # Aggregate results from social footprint for pivoting
        for res in depth_0["social_footprint"]:
            initial_found.extend(res.get("found", []))

    if max_depth == 0 or not initial_found:
        depth_0["pivots_explored"] = []
        depth_0["graph"] = _build_osint_graph(target, input_type, depth_0, [])
        return depth_0

    # Collect pivots from high-confidence results
    visited = {target.lower()}
    all_pivots_data = []

    # We use initial_found which includes aggregated social footprint for NAME search
    current_found = initial_found

    for depth in range(1, max_depth + 1):
        new_pivots = []

        for site_result in current_found:
            if site_result.get("confidence", 0) < 70:
                continue
            for pivot in site_result.get("pivots", []):
                pv = pivot["value"].lower()
                if pv not in visited:
                    visited.add(pv)
                    new_pivots.append({
                        "source_site": site_result["url"],
                        "source_site_name": site_result["site"],
                        "pivot_value": pivot["value"],
                        "pivot_type": pivot["type"],
                        "depth": depth,
                    })

        # Cap pivots per depth level
        new_pivots = new_pivots[:5]

        if not new_pivots:
            break

        # Search each pivot
        for pivot_info in new_pivots:
            try:
                _emit_log(logger, "Running pivot search", phase="recursive", pivot_value=pivot_info["pivot_value"], pivot_type=pivot_info["pivot_type"], depth=depth)
                pivot_results = full_osint_search(pivot_info["pivot_value"], logger=logger, progress_cb=progress_cb)
                pivot_info["results"] = pivot_results
                all_pivots_data.append(pivot_info)
            except Exception as e:
                print(f"[OSINT] Pivot search failed for {pivot_info['pivot_value']}: {e}")
                _emit_log(logger, "Pivot search failed", level="error", phase="recursive", pivot_value=pivot_info["pivot_value"], error=str(e))

        # Update current_found with new pivot results for the next depth
        current_found = []
        for pivot_info in all_pivots_data:
            if pivot_info.get("depth") == depth:
                current_found.extend(pivot_info.get("results", {}).get("found", []))

    # Build graph from all results
    graph = _build_osint_graph(target, input_type, depth_0, all_pivots_data)

    elapsed = (time.time() - start_time) * 1000

    result = {
        **depth_0,
        "search_time_ms": round(elapsed, 2),
        "pivots_explored": [
            {
                "source_site": p["source_site_name"],
                "pivot_value": p["pivot_value"],
                "pivot_type": p["pivot_type"],
                "depth": p["depth"],
                "found_count": p.get("results", {}).get("total_found", 0),
            }
            for p in all_pivots_data
        ],
        "graph": graph,
    }
    _emit_log(logger, "Recursive OSINT search completed", phase="complete", total_found=result.get("total_found", 0), pivots_explored=len(result.get("pivots_explored", [])), search_time_ms=result.get("search_time_ms"))
    return result
