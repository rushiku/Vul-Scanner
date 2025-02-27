import streamlit as st
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to check for missing HTTP headers
def check_http_headers(url):
    headers = [
        'Strict-Transport-Security', 
        'X-Content-Type-Options', 
        'X-XSS-Protection'
    ]
    
    try:
        response = requests.get(url, verify=False)
        missing_headers = [header for header in headers if header not in response.headers]
        
        if missing_headers:
            st.error(f"⚠️ Missing Security Headers: {', '.join(missing_headers)}")
            return False, missing_headers
        else:
            st.success("✅ All security headers are present.")
            return True, []
    
    except requests.exceptions.RequestException as e:
        st.error(f"Error checking headers: {e}")
        return False, []

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a"]
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        
        try:
            response = requests.get(test_url, verify=False)
            sql_errors = ["mysql", "sql syntax", "syntax error", "unclosed quotation", "server error"]

            if any(error in response.text.lower() for error in sql_errors):
                st.error(f"❌ Potential SQL Injection vulnerability detected!")
                return False
        except requests.exceptions.RequestException as e:
            st.error(f"Error testing SQL Injection: {e}")
    
    st.success("✅ No SQL Injection vulnerability detected")
    return True

# Function to test for XSS (Cross-Site Scripting) vulnerability
def test_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "\"'><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>"
    ]
    
    for payload in payloads:
        test_url = f"{url}?search={payload}"
        
        try:
            response = requests.get(test_url, verify=False)
            
            if payload in response.text:
                st.error(f"❌ XSS vulnerability detected!")
                return False
        except requests.exceptions.RequestException as e:
            st.error(f"Error testing XSS: {e}")
    
    st.success("✅ No XSS vulnerability detected")
    return True

# Function to display safety verdict
def website_safety_verdict(safe_headers, missing_headers, safe_sql, safe_xss):
    st.subheader("🔍 **Website Safety Verdict:**")
    issues = []

    if not safe_headers:
        issues.append(f"Missing Security Headers: {', '.join(missing_headers)}")
    if not safe_sql:
        issues.append("SQL Injection vulnerability detected (could allow database access)")
    if not safe_xss:
        issues.append("XSS vulnerability detected (could allow malicious scripts to run)")
    
    if not issues:
        st.success("✅ This website is **SAFE** to use.")
    else:
        st.error("❌ This website has security risks!")
        for issue in issues:
            st.write(f"- {issue}")
        
        if not safe_sql or not safe_xss:
            st.error("❌ This website is **UNSAFE**! **Avoid using it.**")
        else:
            st.warning("⚠️ This website has **some security issues**. **Use with caution.**")

# Main function
def main():
    st.title("🔒 Website Security Checker")
    st.write("This tool checks websites for common security vulnerabilities.")
    
    url = st.text_input("Enter website URL (e.g., http://example.com):", "")
    
    if st.button("Run Security Check"):
        if not url:
            st.warning("Please enter a URL")
            return
        
        with st.spinner("Running security checks..."):
            st.header(f"Scanning: {url}")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.subheader("Security Headers")
                safe_headers, missing_headers = check_http_headers(url)
            
            with col2:
                st.subheader("SQL Injection")
                safe_sql = check_sql_injection(url)
            
            with col3:
                st.subheader("XSS Protection")
                safe_xss = test_xss(url)
            
            st.markdown("---")
            website_safety_verdict(safe_headers, missing_headers, safe_sql, safe_xss)

if __name__ == "__main__":
    main()