# Flask SAML SP Advanced Example

This project demonstrates an advanced SAML Service Provider built with Flask and python3-saml, including:

- SP-initiated SSO
- SP-initiated and IdP-initiated Single Logout (SLO)
- Signed AuthnRequests and LogoutRequests/Responses
- Encrypted Assertions
- Detailed security and metadata configuration

## Prerequisites

- Python 3.7+
- [OpenSSL](https://www.openssl.org/) to generate certificates (if not provided)
- An Identity Provider (IdP) metadata XML or URL

## Setup

1. (Optional but recommended) Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Generate or place your SP certificate and private key under `saml_config/certs/`:
   ```bash
   openssl req -new -x509 -days 3652 -nodes -out saml_config/certs/sp.crt -keyout saml_config/certs/sp.key -subj "/C=US/ST=California/O=MySP/CN=localhost"
   ```
4. Update `saml_config/settings.json` and `saml_config/advanced_settings.json` with your IdP details:
   - Entity ID, SSO/SLO URLs, and IdP x509 certificate.
   - Ensure paths to SP cert/key are correct.

## Running

```bash
python app.py
```

The app listens on http://localhost:5000. Navigate to `/` to start SSO, `/saml/metadata/` to retrieve SP metadata.

## Debugging

- Logs are enabled in debug mode (`settings.json`), inspect console output for incoming/outgoing SAML XML.
- Use browser developer tools to trace redirects and form POSTs.
