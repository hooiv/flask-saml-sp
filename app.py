import os
from flask import Flask, request, redirect, session, url_for, make_response, render_template
from urllib.parse import urlparse
import json
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

# ...existing code imports...

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Use strong secret in production


def load_saml_settings():
    conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml_config')
    with open(os.path.join(conf_path, 'settings.json')) as f:
        settings_data = json.load(f)
    adv_path = os.path.join(conf_path, 'advanced_settings.json')
    if os.path.exists(adv_path):
        with open(adv_path) as f:
            settings_data.update(json.load(f))
    cert_dir = os.path.join(conf_path, 'certs')
    settings_data['sp']['x509cert'] = os.path.join(cert_dir, os.path.basename(settings_data['sp']['x509cert']))
    settings_data['sp']['privateKey'] = os.path.join(cert_dir, os.path.basename(settings_data['sp']['privateKey']))
    return OneLogin_Saml2_Settings(settings=settings_data, custom_base_path=conf_path)


def init_saml_auth(req):
    return OneLogin_Saml2_Auth(req, load_saml_settings())


def prepare_flask_request(request):
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port or (443 if request.scheme == 'https' else 80),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'query_string': request.query_string.decode('utf-8')
    }


@app.route('/')
def index():
    if 'samlUserdata' in session:
        return render_template('index.html', name_id=session['samlNameId'], session_index=session['samlSessionIndex'], attributes=session['samlUserdata'])
    return redirect(url_for('login'))


@app.route('/login')
def login():
    if 'samlUserdata' in session:
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/saml/login/')
def saml_login_request():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return_to = url_for('index', _external=True)
    return redirect(auth.login(return_to=return_to))


@app.route('/saml/acs/', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return f"SAML ACS Error: {auth.get_last_error_reason()}", 400
    if not auth.is_authenticated():
        return "Authentication failed.", 401
    session['samlUserdata'] = auth.get_attributes()
    session['samlNameId'] = auth.get_nameid()
    session['samlSessionIndex'] = auth.get_session_index()
    return redirect(url_for('index'))


@app.route('/saml/logout/')
def saml_logout_request():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    name_id = session.get('samlNameId')
    sess_idx = session.get('samlSessionIndex')
    return_to = url_for('login', _external=True)
    return redirect(auth.logout(name_id=name_id, session_index=sess_idx, return_to=return_to))


@app.route('/saml/slo/', methods=['GET', 'POST'])
def saml_slo():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    redirect_url = auth.process_slo(keep_local_session=True)
    session.clear()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('login'))


@app.route('/saml/metadata/')
def metadata():
    settings = load_saml_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        return f"Metadata Error: {', '.join(errors)}", 500
    resp = make_response(metadata, 200)
    resp.headers['Content-Type'] = 'text/xml'
    return resp


if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)
