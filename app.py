import pandas as pd
import streamlit as st
import requests
import socket
import whois
import re
from urllib.parse import urljoin
from datetime import datetime
from playwright.sync_api import sync_playwright



st.set_page_config(
    page_title="OSINT Investigation Dashboard",
    page_icon="🔎",
    layout="wide"
)
st.title("🔎 OSINT Investigation Dashboard")
st.caption("Open-Source Intelligence • Website Reconnaissance • Security Analysis")
st.divider()

st.subheader("🌐 Website Scanner")

target   = st.text_input(
    "Target Website",
    placeholder="https://example.com",
    help="Enter a website URL to analyze."
)

if st.button("🔍 Start Investigation", use_container_width=True):
    if not target:
        st.warning("Please enter a URL.")
    else:
        start_time = datetime.now()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        try:
            response = requests.get(target, timeout=5)
            hostname = response.url.split("://", 1)[-1].split("/", 1)[0]
            favicon_url = urljoin(response.url, "/favicon.ico")
            try:
                favicon_response = requests.get(favicon_url, timeout=5)
            except requests.RequestException:
                favicon_response = None

            # Target information
            st.subheader("📋 Target Information")

            target_details = {
                "🎯 Target URL": target,
                "🔗 Final URL": response.url,
                "↪️ Redirects": len(response.history),
                "📡 Status": response.status_code,
                "📨 HTTP Method": "GET",
            }

            st.dataframe(
                target_details.items(),
                column_config={
                    0: "Property",
                    1: "Details"
                },
                hide_index=True,
                use_container_width=True
            )
            # Website screenshot
            st.subheader("🖼️ Website Screenshot")

            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page = browser.new_page(
                        viewport={"width": 1280, "height": 720}
                    )
                    page.goto(response.url, wait_until="networkidle", timeout=15000)

                    screenshot = page.screenshot(full_page=True)

                    browser.close()

                st.image(
                    screenshot,
                    caption="Website Preview",
                    use_container_width=True
                )

            except Exception:
                st.warning("Website screenshot could not be captured.")

            st.subheader("🏷️ Website Identity")
            col1, col2 = st.columns([1, 3])

            with col1:
                if favicon_response and favicon_response.ok:
                    st.image(
                        favicon_response.content,
                        caption="Website Logo",
                        width=100
                    )
                else:
                    st.info("No logo")

            with col2:
                st.markdown("### 🌐 Website")
                st.write(hostname)
                st.caption("Website identity and favicon")

        

            if response.status_code == 200:
                st.success("Website is reachable")
            else:
                st.warning(f"Website responded with status {response.status_code}")

            # Website details
            st.subheader("🌐 Website Details")

            server = response.headers.get("Server", "Not provided")
            content_type = response.headers.get("Content-Type", "Not provided")

            # Page title
            start = response.text.lower().find("<title>")
            end = response.text.lower().find("</title>")

            if start != -1 and end != -1:
                title = " ".join(response.text[start + 7:end].split())
            else:
                title = "Not found"

            website_details = {
                "🌍 URL": response.url,
                "🖥️ Hostname": hostname,
                "📡 Status Code": response.status_code,
                "⚙️ Server": server,
                "📄 Content Type": content_type,
                "📦 Response Size": f"{len(response.content):,} bytes",
                "📝 Page Title": title,
            }

            st.dataframe(
                website_details.items(),
                column_config={
                    0: "Property",
                    1: "Details"
                },
                hide_index=True,
                use_container_width=True
            )
            # Hostname
            hostname = target.split("://", 1)[-1].split("/", 1)[0]
            st.write("**Hostname:**", hostname)

            # DNS / IP lookup
            try:
                ip_address = socket.gethostbyname(hostname)
                st.write("**IP Address:**", ip_address)
                dns_status = "Successful"
                st.success("DNS resolution successful")
            except socket.gaierror:
                ip_address = "Could not resolve"
                dns_status = "Failed"
                st.error("DNS resolution failed")

            # HTTPS check
            if target.startswith("https://"):
                https_status = "Enabled"
                st.success("🔒 HTTPS is enabled")
            else:
                https_status = "Not enabled"
                st.warning("⚠️ HTTPS is not being used")

            st.subheader("📊 Investigation Summary")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("📡 Status", response.status_code)

            with col2:
                st.metric("🌍 IP Address", ip_address)

            with col3:
                st.metric("🔒 HTTPS", https_status)

            with col4:
                st.metric("🌐 DNS", dns_status)

            # Response headers
            st.subheader("📡 Response Headers")
            if response.headers:
                header_data = []
                age_found = False

                for key, value in response.headers.items():
                    if key.lower() == "age":
                        age_found = True

                    display_value = value

                    # Make Age header easier to understand
                    if key.lower() == "age":
                        try:
                            age_seconds = int(value)
                            minutes = age_seconds // 60
                            seconds = age_seconds % 60
                            display_value = f"{minutes} min {seconds} sec"
                        except ValueError:
                            display_value = value

                    header_data.append({
                        "Header": key,
                        "Value": display_value
                    })

                if not age_found:
                    header_data.insert(0, {
                        "Header": "Age",
                        "Value": "Not provided by server"
                    })

                if header_data:
                    st.dataframe(
                        header_data,
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "Header": st.column_config.TextColumn(
                                "Header",
                                width="medium"
                            ),
                            "Value": st.column_config.TextColumn(
                                "Value",
                                width="large"
                            )
                        }
                    )
                else:
                    st.info("No response headers found.")
            else:
                st.warning("No response headers were returned.")

            st.subheader("🛡️ Security Headers")
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options"
            ]
            security_score = sum(1 for header in security_headers if header in response.headers)
            st.write(f"**Security Header Score:** {security_score}/3")
            # Scan Summary Chart
            st.subheader("📊 Scan Summary")

            chart_data = pd.DataFrame({
                "Check": ["DNS", "HTTPS", "Security Headers"],
                "Score": [
                    1 if dns_status == "Successful" else 0,
                    1 if response.url.lower().startswith("https://") else 0,
                    security_score / 3
                ]
            })

            st.bar_chart(
                chart_data.set_index("Check")
            )
            st.subheader("🛡️ Security Header Details")

            security_header_labels = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Content-Type-Options": "X-Content-Type-Options",
            }

            for header, label in security_header_labels.items():
                value = response.headers.get(header)

                if value:
                    st.success(f"✅ {label}: Present")
                    st.caption(value)
                else:
                    st.warning(f"⚠️ {label}: Not provided")

            # WHOIS information
            st.subheader("📜 WHOIS Information")
            try:
                whois_domain = hostname[4:] if hostname.startswith("www.") else hostname
                domain_info = whois.whois(whois_domain)

                registrar = domain_info.registrar or "Not available"
                creation_date = domain_info.creation_date or "Not available"
                expiration_date = domain_info.expiration_date or "Not available"
                country = domain_info.country or "Not available"

                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                whois_details = {
                    "🏢 Registrar": registrar,
                    "📅 Creation Date": creation_date,
                    "⏳ Expiration Date": expiration_date,
                    "🌍 Country": country,
                }

                st.dataframe(
                    whois_details.items(),
                    column_config={
                        0: "Property",
                        1: "Details"
                    },
                    hide_index=True,
                    use_container_width=True
                )
            except Exception:
                registrar = "Not available"
                creation_date = "Not available"
                expiration_date = "Not available"
                country = "Not available"
                st.warning("WHOIS information is not available.")

            hsts_status = "Present" if "Strict-Transport-Security" in response.headers else "Not detected"
            csp_status = "Present" if "Content-Security-Policy" in response.headers else "Not detected"
            xcto_status = "Present" if "X-Content-Type-Options" in response.headers else "Not detected"

            scan_time = (datetime.now() - start_time).total_seconds()

            # Download report
            report = f"""
========================================
       OSINT INVESTIGATION REPORT
========================================

TARGET
----------------------------------------
Target URL: {target}
Final URL: {response.url}
HTTP Method: GET
HTTP Status: {response.status_code}
Redirects: {len(response.history)}

WEBSITE
----------------------------------------
Hostname: {hostname}
IP Address: {ip_address}
Server: {server}
Content Type: {content_type}
Page Title: {title}
Response Size: {len(response.content):,} bytes

SECURITY
----------------------------------------
security Header Score: {security_score}/3
HTTPS: {https_status}
Strict-Transport-Security: {hsts_status}
Content-Security-Policy: {csp_status}
X-Content-Type-Options: {xcto_status}

WHOIS
----------------------------------------
Registrar: {registrar}
Creation Date: {creation_date}
Expiration Date: {expiration_date}
Country: {country}

SCAN
----------------------------------------
Scan Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Scan Duration: {scan_time:.2f} seconds

RESPONSE HEADERS
----------------------------------------

"""

            for key, value in response.headers.items():
                if key.lower() == "age":
                    try:
                        age_seconds = int(value)
                        minutes = age_seconds // 60
                        seconds = age_seconds % 60
                        report += f"Age: {minutes} minutes {seconds} seconds\n"
                    except ValueError:
                        report += f"Age: {value}\n"
                else:
                    report += f"{key}: {value}\n"

            st.subheader("📥 Investigation Report")

            st.caption(
                "Your OSINT investigation is complete. "
                "Download the full results as a text report."
            )

            st.download_button(
                label="📥 Download Investigation Report",
                data=report,
                file_name="osint_investigation_report.txt",
                mime="text/plain",
                use_container_width=True
            )

            st.caption(f"⏱️ Scan completed in {scan_time:.2f} seconds")
        except requests.RequestException as error:
            st.error(f"Could not reach this website: {error}")

st.divider()

st.info(
    "⚠️ Use this prototype only with public information "
    "and systems you are authorized to investigate."
)
st.divider()

st.caption("🔎 OSINT Investigation Prototype • Passive public-source analysis")