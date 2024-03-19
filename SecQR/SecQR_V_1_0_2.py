import cv2
from omegaconf import OmegaConf
import google.generativeai as palm
import requests
import json
import re

import segno

# Configuration
debug = 0
conf = OmegaConf.load('secrets.yaml')
# LLM configuration
model_id = conf.google_api.model
palm.configure(api_key=conf.google_api.api_token)

# URL pattern configuration
url_pattern = r"(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)"

# OpenCV configuration
camera_id = 0
delay = 1
window_name = 'SecQR V 1.0.2'

qcd = cv2.QRCodeDetector()
cap = cv2.VideoCapture(camera_id)

def mfa(s):
    # MFA
    pin = input("Enter your PIN: ")
    if pin != "1234":  # Replace with actual PIN verification
        print("Invalid PIN")
    else:
        print("PIN verified")
        print(f'Decrypted Message: {s}')

def url_safety(s):
    # URL Safety Validation
    response = requests.get(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={conf.google_api.api_token}", json={
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": s}
            ]
        }
    })
    try:
        if response.json():
            print("!!! Unsafe URL detected !!!")
        else:
            print("URL is safe")
    except json.decoder.JSONDecodeError:
        print("URL is safe")

def vulnerability_scan(s):
    query = f"""
    The following are the types of vulnerabilities
    1.SQL Injection
    2.Cross-Site Scripting (XSS)
    3.Command Injection
    4.Format String Vulnerabilities
    5.XML External Entity Injection (XXE)
    6.String Fuzzing
    7.Server-Side Includes (SSI) Injection
    8.Local File Inclusion (LFI) & Directory Traversal
    9.Custom vulnerabilities specified through a wordlist
    10. Other vulnerabilites

    Please evaluate the below message and classify the type of vulnerability from the above list and give the answers properly formatted

    message:
    {s}

    Give the output in the below format 
    1. Type of vulnerability :
    2. Severity in the scale of 1-10 :
    3. Brief Description :
    """
    completion = palm.generate_text(model=model_id,
                                    prompt=query,
                                    temperature=0.0)
    print(f'Scanned Data : {s}')
    print(completion.result)

while True:
    ret, frame = cap.read()
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    if ret:
        ret_qr, decoded_info, points, _ = qcd.detectAndDecodeMulti(gray)
        if ret_qr:
            # cv2.imwrite('qr_code.png', gray)
            for s, p in zip(decoded_info, points):
                if s and debug == 0:
                    color = (0, 255, 0)
                    if re.match(r'^PIN', s):
                        mfa(s)
                    elif re.match(url_pattern, s):
                        urls = re.findall(url_pattern, s)
                        if urls:
                            for url in urls:
                                url_safety(url)
                    else:
                        vulnerability_scan(s)
                else:
                    color = (0, 0, 255)
                frame = cv2.polylines(frame, [p.astype(int)], True, color, 8)
        cv2.imshow(window_name, frame)

    if cv2.waitKey(delay) & 0xFF == ord('q'):
        break

cv2.destroyWindow(window_name)