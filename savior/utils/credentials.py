"""Credential helpers for interactive task execution."""

import getpass
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse


def get_t1_credentials(url, step=1):
    """Get interactive T1 credentials.

    Email and username may be cached to connect T1 step1 and step2 across
    runs, but passwords are always collected via getpass and never written
    to disk.
    """
    domain = get_domain_name(url)
    cred_file = Path(os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))) / f"oauth_test_t1_{domain}.json"

    if cred_file.exists():
        try:
            with open(cred_file, "r", encoding="utf-8") as handle:
                saved = json.load(handle)

            if step == 1:
                print(f"\nFound saved credentials for this domain:")
                print(f"  Email: {saved.get('Email', 'N/A')}")
                if "Username" in saved:
                    print(f"  Username: {saved['Username']}")

                use_saved = input("Use saved email and username? (Y/n): ").strip()
                if use_saved == "" or use_saved.lower() == "y":
                    print("\nPlease enter registration password (for website registration):")
                    registration_password = getpass.getpass("Registration Password: ").strip()
                    return {
                        "Email": saved.get("Email", ""),
                        "Password": registration_password,
                        "Username": saved.get("Username", ""),
                    }
            else:
                print(f"\nFound saved credentials for this domain:")
                print(f"  Email: {saved.get('Email', 'N/A')}")

                use_saved = input("Use saved email? (Y/n): ").strip()
                if use_saved == "" or use_saved.lower() == "y":
                    print("\nPlease enter Gmail password (for OAuth login):")
                    gmail_password = getpass.getpass("Gmail Password: ").strip()
                    return {
                        "Email": saved.get("Email", ""),
                        "Password": gmail_password,
                    }
        except Exception:
            print("Error reading saved credentials, will prompt for new ones.")

    if step == 1:
        print("\nPlease enter credentials for T1_step1 test:")
        print("(These will be used for website registration)")
        email = input("Email: ").strip()
        registration_password = getpass.getpass("Registration Password (for website registration): ").strip()
        username = input("Username (optional, press Enter to skip): ").strip()
        cred_data = {
            "Email": email,
            "Username": username,
        }
        with open(cred_file, "w", encoding="utf-8") as handle:
            json.dump(cred_data, handle, ensure_ascii=False, indent=2)
        return {"Email": email, "Password": registration_password, "Username": username}

    print("\nPlease enter credentials for T1_step2 test:")
    print("(These will be used for Google OAuth login)")
    email = input("Email (should be same as T1_step1): ").strip()
    gmail_password = getpass.getpass("Gmail Password (for OAuth login): ").strip()
    if cred_file.exists():
        try:
            with open(cred_file, "r", encoding="utf-8") as handle:
                cred_data = json.load(handle)
        except Exception:
            cred_data = {}
    else:
        cred_data = {}

    cred_data["Email"] = email
    with open(cred_file, "w", encoding="utf-8") as handle:
        json.dump(cred_data, handle, ensure_ascii=False, indent=2)
    return {"Email": email, "Password": gmail_password}


def get_secure_input(prompt):
    """Get secure input with standard `getpass` prompt formatting."""
    prompt_clean = prompt.rstrip(" :")
    return getpass.getpass(f"{prompt_clean}: ")


def get_domain_name(url):
    """Extract the sanitized domain name used by task scripts."""
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or url
        domain = re.sub(r"^www\.", "", domain)
        parts = domain.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
        return domain.replace(".", "_")
    except Exception:
        return re.sub(r"[^a-zA-Z0-9-.]", "_", url)
