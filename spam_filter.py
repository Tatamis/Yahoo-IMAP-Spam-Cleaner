import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import re
import random
import time
import unicodedata
import requests

# ================= CONFIGURATION =================
EMAIL = "your_email@yahoo.com"
APP_PASSWORD = "put_your_app_password_here"
IMAP_SERVER = "imap.mail.yahoo.com" # Change if using a different provider (e.g., imap.gmail.com)

# --- VIRUSTOTAL CONFIGURATION ---
VT_API_KEY = "put_your_virustotal_api_key_here"
VT_MIN_MALICIOUS_VOTES = 2

# Set to False for actual deletion/moving
DRY_RUN = False 
MAX_EMAILS_TO_CHECK = 1000 
FOLDERS_TO_SCAN = ["inbox", '"Bulk Mail"', "Bulk", "Spam", "Junk"]

# ================= BLOCKING CRITERIA =================
BLOCKED_DOMAINS = {
    # e.g., "spammer.com", "bad-casino.net"
}

SPAM_KEYWORDS = re.compile(
    # e.g., r'(bitcoin|lottery|viagra|hot singles)',
    r'dummy_placeholder', re.IGNORECASE
)

URL_REGEX = re.compile(r'https?://[^\s<>"\'{}|\\^`]+')
SAFE_DOMAINS = [
    "google.com", "yahoo.com", "bing.com", "facebook.com", "instagram.com", 
    "twitter.com", "x.com", "youtube.com", "apple.com", "microsoft.com"
]

def normalize_text(text):
    if not text: return ""
    text_without_diacritics = ''.join(
        c for c in unicodedata.normalize('NFD', text) if unicodedata.category(c) != 'Mn'
    )
    return re.sub(r'\s+', ' ', text_without_diacritics)

def decode_str(header_value):
    if not header_value: return ""
    header_str = ""
    for fragment, encoding in decode_header(header_value):
        if isinstance(fragment, bytes):
            try: header_str += fragment.decode(encoding or "utf-8", errors="ignore")
            except LookupError: header_str += fragment.decode("latin-1", errors="ignore")
        else: header_str += str(fragment)
    return header_str

def check_spoofed_sender(from_header):
    real_name, actual_email = parseaddr(from_header)
    # Automatically extracts the username from your configured EMAIL (e.g., 'john.doe' from 'john.doe@yahoo.com')
    target_name = EMAIL.split('@')[0].lower()
    
    if target_name in real_name.lower() or target_name in actual_email.lower():
        if actual_email.lower() != EMAIL.lower():
            return True, f"Name Spoofing: Comes from {actual_email}"
    return False, ""

def check_blocked_domain(from_header):
    _, actual_email = parseaddr(from_header)
    actual_email = actual_email.lower()
    if "@" in actual_email:
        domain = actual_email.split('@')[1]
        for blocked in BLOCKED_DOMAINS:
            if domain == blocked or domain.endswith("." + blocked):
                return True, f"Explicitly blocked domain: {domain}"
    return False, ""

def check_email_auth(msg):
    auth_header = str(msg.get("Authentication-Results", "")).lower()
    spf_header = str(msg.get("Received-SPF", "")).lower()
    if "dmarc=fail" in auth_header or "spf=fail" in auth_header or "spf: fail" in spf_header: return True, "Auth Hard Fail (SPF/DMARC failed)."
    if "spf=softfail" in auth_header or "spf: softfail" in spf_header: return True, "Auth Soft Fail (SPF Softfail)."
    if "spf=none" in auth_header or "spf: none" in spf_header: return True, "Auth Missing (No SPF configured)."
    return False, ""

def get_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                payload = part.get_payload(decode=True)
                if payload: body += payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload: body = payload.decode(errors="ignore")
    return body

def analyze_urls_in_body(body_text):
    urls = URL_REGEX.findall(body_text)
    suspicious_urls = set()
    for url in urls:
        url_lower = url.lower()
        domain_match = re.search(r'https?://(?:www\.)?([^/:\?]+)', url_lower)
        if not domain_match: continue
        url_domain = domain_match.group(1)
        
        is_blocked = False
        for blocked in BLOCKED_DOMAINS:
            if url_domain == blocked or url_domain.endswith("." + blocked):
                is_blocked = True
                break
        if is_blocked:
            return True, url_domain, [] 
            
        is_safe = False
        for safe in SAFE_DOMAINS:
            if url_domain == safe or url_domain.endswith("." + safe):
                is_safe = True
                break
                
        if not is_safe and not is_blocked:
            suspicious_urls.add(url)
            
    return False, "", list(suspicious_urls)

def check_url_virustotal(url):
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        print(f"      [VT DEBUG] Sending to API -> URL: {url[:60]}...")
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 429:
            print("      [VT DEBUG] ⚠️ VirusTotal rate limit reached. Skipping.")
            return False, ""
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            total_bad = stats.get('malicious', 0) + stats.get('phishing', 0) + stats.get('suspicious', 0)
            if total_bad >= VT_MIN_MALICIOUS_VOTES:
                return True, f"VirusTotal marked URL as malicious (Score: {total_bad})."
        return False, ""
    except Exception as e:
        print(f"      [VT DEBUG] API Error: {e}")
        return False, ""

def connect_imap(retries=5):
    """Attempts to connect to the IMAP server, with increasing delays if the server refuses."""
    for attempt in range(retries):
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL, APP_PASSWORD)
            return mail
        except Exception as e:
            err_str = str(e)
            wait_time = 15 * (attempt + 1)
            print(f"\n      [LOGIN ERROR] Server rejected the connection: {err_str}")
            if attempt < retries - 1:
                print(f"      ⏳ Waiting {wait_time} seconds before retrying...")
                time.sleep(wait_time)
            else:
                raise Exception(f"Final login failure after {retries} attempts.")

def run_filter():
    mail = None
    try:
        mail = connect_imap()
        total_processed_count = 0

        for folder in FOLDERS_TO_SCAN:
            status, _ = mail.select(folder)
            if status != "OK": continue

            status, messages = mail.uid('SEARCH', None, "ALL")
            if status != "OK" or not messages[0]: continue

            uids = [id.decode() for id in messages[0].split()]
            recent_uids = uids[-MAX_EMAILS_TO_CHECK:]
            
            clean_folder_name = folder.strip('\"')
            print(f"\n=======================================================")
            print(f"📁 Scanning the last {len(recent_uids)} emails from [{clean_folder_name}]...")
            print(f"=======================================================")
            
            deleted_count = 0

            for e_uid in recent_uids:
                if total_processed_count > 0 and total_processed_count % 150 == 0:
                    sleep_time = random.randint(60, 180)
                    print(f"\n⏳ [SAFETY] Processed {total_processed_count} emails. Closing connection and pausing for {sleep_time // 60} minutes...")
                    try:
                        mail.close()
                        mail.logout()
                    except: pass
                    
                    time.sleep(sleep_time)
                    
                    print(f"🔄 Reconnecting to server after pause...")
                    try:
                        mail = connect_imap()
                        mail.select(folder)
                    except Exception as e:
                        print(f"🚨 Severe reconnection failure: {e}. Moving to the next email to trigger retry...")

                success = False
                retries = 2
                
                while not success and retries > 0:
                    try:
                        total_processed_count += 1 if retries == 2 else 0 
                        
                        res, msg_data = mail.uid('FETCH', e_uid, "(RFC822)")
                        if res != "OK" or not msg_data:
                            success = True 
                            continue
                            
                        for response_part in msg_data:
                            if isinstance(response_part, tuple):
                                msg = email.message_from_bytes(response_part[1])
                                
                                from_header = decode_str(msg.get("From"))
                                subject = decode_str(msg.get("Subject"))
                                
                                print(f"\n[{total_processed_count}] Analyzing email...")

                                _, actual_email = parseaddr(from_header)
                                if actual_email.lower() == EMAIL.lower():
                                    print(f"✅ [{total_processed_count}] OK (SELF-SENT) [{clean_folder_name}] -> Subject: {subject[:40]}...")
                                    continue 
                                
                                is_spam = False
                                spam_reason = ""

                                # 1. Spoofing Filter
                                spoofed, reason = check_spoofed_sender(from_header)
                                if spoofed:
                                    is_spam, spam_reason = True, reason
                                    
                                # 2. Blocked Domains Filter
                                elif not is_spam:
                                    domain_blocked, domain_reason = check_blocked_domain(from_header)
                                    if domain_blocked:
                                        is_spam, spam_reason = True, domain_reason
                                        
                                # 3. Auth Filter (SPF/DMARC)
                                elif not is_spam:
                                    auth_failed, auth_reason = check_email_auth(msg)
                                    if auth_failed:
                                        is_spam, spam_reason = True, auth_reason
                                        
                                # 4. Empty Subject Filter
                                elif not is_spam:
                                    subject_norm = normalize_text(subject).strip()
                                    if not subject_norm:
                                        is_spam, spam_reason = True, "Email has no subject (Empty Subject)."
                                        
                                # 5. Subject Keywords Filter
                                elif not is_spam:
                                    if SPAM_KEYWORDS.search(subject_norm):
                                        is_spam, spam_reason = True, "Spam keywords found in subject."
                                        
                                # 6. Body Filter (Keywords + VirusTotal URLs)
                                elif not is_spam:
                                    body = get_email_body(msg)
                                    body_norm = normalize_text(body)
                                    if SPAM_KEYWORDS.search(body_norm):
                                        is_spam, spam_reason = True, "Spam keywords found in body."
                                    else:
                                        is_domain_blocked, domain_found, suspicious_urls = analyze_urls_in_body(body)
                                        if is_domain_blocked:
                                            is_spam, spam_reason = True, f"Blocked domain URL in body: {domain_found}"
                                        elif suspicious_urls:
                                            url_to_check = suspicious_urls[0]
                                            is_malicious, vt_reason = check_url_virustotal(url_to_check)
                                            if is_malicious:
                                                is_spam, spam_reason = True, vt_reason
                                            time.sleep(15)

                                if is_spam:
                                    print(f"🚨 [{total_processed_count}] SPAM (MOVED) [{clean_folder_name}] Reason: {spam_reason}")
                                    print(f"   -> From: {from_header}")
                                    if not DRY_RUN:
                                        mail.uid('COPY', e_uid, "Trash")
                                        mail.uid('STORE', e_uid, '+FLAGS', '\\Deleted')
                                        deleted_count += 1
                                else:
                                    print(f"✅ [{total_processed_count}] OK (KEPT) [{clean_folder_name}] -> Subject: {subject[:40]}...")
                                        
                        success = True 
                        
                    except Exception as loop_err:
                        print(f"      [NETWORK ERROR] Connection lost at email [{total_processed_count}]. Reconnecting...")
                        try:
                            mail = connect_imap()
                            mail.select(folder)
                        except: pass
                        retries -= 1
                            
            if not DRY_RUN and deleted_count > 0:
                mail.expunge() 
                print(f"\n🗑️  Moved {deleted_count} spam emails to Trash from [{clean_folder_name}].")

    except Exception as e:
        print(f"Fatal general error: {e}")
    finally:
        if mail:
            try:
                mail.close()
                mail.logout()
            except: pass
        print("\n🏁 Cleanup task completed successfully.")

if __name__ == "__main__":
    run_filter()
