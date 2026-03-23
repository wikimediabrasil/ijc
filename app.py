import io
import os
import yaml
import math
import locale
import hashlib
import requests
from flask import Flask, render_template, request, redirect, url_for, session, make_response, Response, g
from fpdf import FPDF
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from requests_oauthlib import OAuth1Session
from oauth_wiki import get_username
from sqlalchemy_utils import StringEncryptedType
import PyPDF2

from email.message import EmailMessage
import ssl
import smtplib
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText

USER_AGENT = "IJC (https://w.wiki/3H3G)"

__dir__ = os.path.dirname(__file__)
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {'activities': 'sqlite:///users.db'}
app.config.update(yaml.safe_load(open(os.path.join(__dir__, 'config.yaml'))))

# Initialize the database
db = SQLAlchemy(app)

key = app.config["ENCRYPTION_KEY"]

MODULES = [
    "https://pt.wikiversity.org/wiki/Introdução_ao_Jornalismo_Científico/Metodologia_e_Filosofia_da_Ciência/Atividade/",
    "https://outreachdashboard.wmflabs.org/courses/CEPID_NeuroMat/Introdu%C3%A7%C3%A3o_ao_Jornalismo_Cient%C3%ADfico/students/articles/",
    "https://pt.wikiversity.org/wiki/Introdução_ao_Jornalismo_Científico/Ética_da_Ciência/Atividade/",
    "https://pt.wikiversity.org/wiki/Introdução_ao_Jornalismo_Científico/Temas_Centrais_da_Ciência_Contemporânea/Atividade/",
    "https://pt.wikiversity.org/wiki/Introdução_ao_Jornalismo_Científico/Modos_de_Organização_e_Financiamento_dos_Sistemas_de_Pesquisa,_no_Brasil_e_no_Exterior/Atividade/",
    "https://pt.wikiversity.org/wiki/Introdução_ao_Jornalismo_Científico/Mídias,_Linguagens_e_Prática_do_Jornalismo_Científico/Atividade/",
]

# Create database (db) model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    full_name = db.Column(StringEncryptedType(db.String(300), key), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow())
    date_modified = db.Column(db.DateTime, default=datetime.utcnow())
    can_download_certificate = db.Column(db.String(), nullable=False)
    solicited_certificate = db.Column(db.Boolean, nullable=False, default=False)


class SubsPDF(FPDF):
    def header(self):
        self.image(os.path.join(app.static_folder, 'A_los_derechos_humanos_cropped.jpg'), x=0, y=0, w=210, h=32)
        # Box for the title
        self.set_draw_color(0, 104, 163)
        self.set_fill_color(0, 104, 163)    # Blue box as background for the title
        self.set_text_color(255, 255, 255)  # Title in white color
        self.set_font('Times', 'B', 15)     # Title in Times New Roman, bold, 15pt
        # Title text
        self.set_x(30)
        self.cell(w=150, h=12, border=0, ln=1, align='C', fill=True, txt='INTRODUÇÃO AO JORNALISMO CIENTÍFICO')

    def footer(self):
        username = get_username()
        user = Users.query.filter_by(username=username).first()
        date_modified = user.date_modified
        user_hash = hashlib.sha1(bytes("Subscription " + username + str(date_modified), 'utf-8')).hexdigest()
        self.set_y(-16.5)
        self.set_font('Times', '', 8.8)
        self.cell(w=0, h=6.5, border=0, ln=1, align='C',
                  txt='A validade deste documento pode ser checada em https://ijc.toolforge.org/. '
                      'O código de validação é: ' + user_hash)
    pass


class CertificationPDF(FPDF):
    def header(self):
        self.image(os.path.join(app.static_folder, 'background_certificado.jpg'), x=0, y=0, w=297, h=210)

    def footer(self):
        username = get_username()
        user = Users.query.filter_by(username=username).first()
        date_modified = user.date_modified
        user_hash = hashlib.sha1(bytes("Certificate " + username + str(date_modified), 'utf-8')).hexdigest()
        self.set_y(-16.5)
        self.set_font('Merriweather', '', 8.8)
        self.cell(w=0, h=6.5, border=0, ln=1, align='C',
                  txt='A validade deste documento pode ser checada em https://ijc.toolforge.org/. '
                      'O código de validação é: ' + user_hash)
    pass


########################################################################################################################
# L O G I N
########################################################################################################################
@app.before_request
def init_profile():
    g.profiling = []


@app.before_request
def global_user():
    g.user = get_username()


@app.route('/login')
def login():
    """
    This function creates an OAuth session and sends the user
    to the authorization special webpage in ptwikiversity so
    the user can give permission for the tool to operate.

    :return: redirects the user to the authorization special
    webpage on ptwikiversity.
    """

    next_page = request.args.get('next')

    if next_page:
        session['after_login'] = next_page

    client_key = app.config['CONSUMER_KEY']
    client_secret = app.config['CONSUMER_SECRET']

    base_url = 'https://pt.wikiversity.org/w/index.php'
    request_token_url = base_url + '?title=Special%3aOAuth%2finitiate'

    oauth = OAuth1Session(client_key,
                          client_secret=client_secret,
                          callback_uri='oob')

    fetch_response = oauth.fetch_request_token(request_token_url)

    session['owner_key'] = fetch_response.get('oauth_token')
    session['owner_secret'] = fetch_response.get('oauth_token_secret')

    base_authorization_url = 'https://pt.wikiversity.org/wiki/Special:OAuth/authorize'
    authorization_url = oauth.authorization_url(base_authorization_url,
                                                oauth_consumer_key=client_key)

    return redirect(authorization_url)


@app.route("/oauth-callback", methods=["GET"])
def oauth_callback():
    """
    This function stores the authorization tokens of the
    users and redirects them to the page they were before
    the logging in process.

    :return: redirects the users to the page they were
    before logging in and authorizating the tool.
    """

    base_url = 'https://pt.wikiversity.org/w/index.php'
    client_key = app.config['CONSUMER_KEY']
    client_secret = app.config['CONSUMER_SECRET']

    oauth = OAuth1Session(client_key,
                          client_secret=client_secret,
                          resource_owner_key=session['owner_key'],
                          resource_owner_secret=session['owner_secret'])

    oauth_response = oauth.parse_authorization_response(request.url)
    verifier = oauth_response.get('oauth_verifier')
    access_token_url = base_url + '?title=Special%3aOAuth%2ftoken'

    oauth = OAuth1Session(client_key,
                          client_secret=client_secret,
                          resource_owner_key=session['owner_key'],
                          resource_owner_secret=session['owner_secret'],
                          verifier=verifier)

    oauth_tokens = oauth.fetch_access_token(access_token_url)
    session['owner_key'] = oauth_tokens.get('oauth_token')
    session['owner_secret'] = oauth_tokens.get('oauth_token_secret')
    next_page = session.get('after_login')

    return redirect(next_page)


########################################################################################################################
# P A G E S
########################################################################################################################
# Sobre
@app.route('/about')
def about():
    """
    This function shows a page describing the Introdução ao Jornalismo Científico course and tool

    :return: A html page with the about content.
    """

    username = get_username()
    return render_template('about.html',
                           username=username)


# Página inicial
@app.route('/')
def home():
    """
    This function shows the homepage for the Introdução ao Jornalismo Científico tool

    :return: A html page with the initial content.
    """

    username = get_username()
    return render_template('home.html',
                           username=username)


# Inscrição
@app.route('/subscription', methods=['POST', 'GET'])
def subscription():
    """
    This page shows a webpage with the letter of subscription

    :return: A html page with a form for subscription
    """

    username = get_username()

    if username:
        if request.method == 'POST':
            user_name = request.form['Username']
            full_name = request.form['FullName']
            modules_activities = ["NP" for i in range(app.config["NUMBER_OF_MODULES"])]

            new_subscription = Users(username=user_name,
                                     full_name=full_name,
                                     can_download_certificate=";".join(modules_activities))

            # Try to push it to the database
            try:
                db.session.add(new_subscription)
                db.session.commit()
                return redirect(url_for('subscription'))
            except:
                return 'Ocorreu um erro!'
        else:
            user_is_registered = Users.query.filter_by(username=username).first()
            return render_template('subscription.html',
                                   username=username,
                                   user_is_registered=user_is_registered)
    else:
        return redirect(url_for('home'))


# Atualizar inscrição
@app.route('/update_subscription/<user_username>', methods=['POST', 'GET'])
def update_subscription(user_username):
    """
    This function shows a page for the coordinator update users full name

    :return: A html page with a form for updating the user subscription
    """

    username = get_username()
    allowed_usernames = list(app.config["COORDINATORS_USERNAMES"]) + [user_username]
    if username in allowed_usernames:
        user_to_update = Users.query.filter_by(username=user_username).first()

        if request.method == 'POST':
            user_to_update.full_name = request.form["FullName"]
            user_to_update.date_modified = datetime.utcnow()

            modules_activities = ["F" for i in range(app.config["NUMBER_OF_MODULES"])]
            user_to_update.can_download_certificate = ";".join(modules_activities)

            # Try to push it to the database
            try:
                db.session.commit()
                return redirect(url_for('subscription'))
            except:
                return 'Ocorreu um erro!'
        else:
            return render_template('update_subscription.html',
                                   username=username,
                                   user=user_to_update)
    else:
        return redirect(url_for('home'))


# Gerar carta de inscrição
@app.route('/subscription_letter', methods=['GET'])
def subscription_letter():
    """
    This function generates a pdf file with a letter of subscription in the course

    :return: A pdf file with a letter of subscription
    """

    username = get_username()

    if username:
        # Create page
        pdf = SubsPDF(orientation='P', unit='mm', format='A4')
        pdf.add_page()

        #######################################################################################################
        # Data
        #######################################################################################################
        pdf.set_xy(10, 42)                          # Start the letter text at the 10x42mm point

        pdf.set_font('Times', '', 13)               # Text of the body in Times New Roman, regular, 13 pt

        locale.setlocale(locale.LC_TIME, "pt_BR")   # Setting the language to portuguese for the date
        pdf.cell(w=150, h=6, border=0, ln=1, align='L',
                 txt='São Paulo, ' + datetime.now().strftime("%d de %B de %Y"))

        pdf.cell(w=0, h=6, ln=1)                  # New line

        #######################################################################################################
        # A quem possa interessar
        #######################################################################################################
        pdf.set_font('Times', 'B', 13)              # Text of the addressing in Times New Roman, bold, 13 pt
        pdf.cell(w=150, h=6, txt='A quem possa interessar', border=0, ln=1, align='L')

        pdf.cell(w=0, h=6, ln=1)                  # New line

        #######################################################################################################
        # User data
        #######################################################################################################
        user = Users.query.filter_by(username=username).first()

        name = user.full_name                                       # User full name

        #######################################################################################################
        # Text
        #######################################################################################################
        pdf.set_font('Times', '', 13)               # Text of the body in Times New Roman, regular, 13 pt
        pdf.multi_cell(w=0,
                       h=6,
                       txt="O curso de Introdução ao Jornalismo Científico, desenvolvido pelo Centro de Pesquisa, Inovação "
                           "e Difusão em Neuromatemática com o apoio da FAPESP e do Wiki Movimento Brasil, está disponível "
                           "em uma plataforma de educação aberta, a Wikiversidade.\n\n"
                           "As aulas foram realizadas, com orientação científica da equipe de pesquisa do CEPID NeuroMat, "
                           "por bolsistas de jornalismo científico da FAPESP. O objetivo do curso é capacitar profissio"
                           "nais de comunicação na cobertura jornalística especializada em ciência. Está também direciona"
                           "do ao atendimento ao exposto no edital Mídia Ciência, da FAPESP.\n\n"
                           "O curso é livre e o controle das atividades é realizado por recursos na Wikimedia. "
                           "Esta carta certifica que "
                           + name +
                           " está apto(a) a participar do curso de Introdução ao "
                           "Jornalismo Científico e comprova sua matrícula, pela plataforma de registro IJC (https://ijc.toolforge.org).\n\n"
                           "Atestamos para os devidos fins, portanto, que "
                           + name +
                           " realiza o curso de Introdução ao Jornalismo Científico. A realização do curso pode ser verificada "
                           "na página de acompanhamento das atividades, que monitora o progresso do(a) estudante:\n",
                       border=0,
                       align='J')
        outreach_link = "https://outreachdashboard.wmflabs.org/courses/CEPID_NeuroMat/Introdução_ao_Jornalismo_Científico/students/articles/" + username
        safe_outreach_link = "https://outreachdashboard.wmflabs.org/courses/CEPID_NeuroMat/Introdu%C3%A7%C3%A3o_ao_Jornalismo_Cient%C3%ADfico/students/articles/" + username
        pdf.multi_cell(w=0,
                       h=6,
                       txt=outreach_link + "\n\n",
                       border=0,
                       align='J')
        x = pdf.get_x()
        y = pdf.get_y()
        w = pdf.get_string_width(outreach_link)
        h = 6
        pdf.link(x=x,
                 y=y-3*h,
                 w=w,
                 h=2*h,
                 link=safe_outreach_link)
        pdf.multi_cell(w=0,
                       h=6,
                       txt="Caso requisitado, podemos emitir uma declaração de conclusão do curso, uma vez que o(a) "
                           "participante tenha finalizado todas as leituras e tarefas.\n\n"
                           "Por favor, não hesitem em entrar em contato conosco para receber outras informações a respeito "
                           "do curso.\n\n"
                           "Atenciosamente,",
                       border=0,
                       align='J')

        #######################################################################################################
        # Footer
        #######################################################################################################
        pdf.cell(w=0, h=13, ln=1)                   # Give some space for the signatures
        # Fernando da Paixão signature
        pdf.image(os.path.join(app.static_folder, 'fpaixao.png'), x=37.5, y=234, w=35, h=16)
        pdf.set_y(240)
        pdf.multi_cell(w=90,
                       h=6,
                       txt="_____________________________________\n"
                           "FERNANDO JORGE DA\nPAIXÃO FILHO\nCoordenador da equipe de\ndifusão do CEPID NeuroMat",
                       border=0,
                       align='C')

        # João Alexandre Peschanski signature
        pdf.image(os.path.join(app.static_folder, 'jap.png'), x=137.5, y=236, w=35, h=16)
        pdf.set_xy(110, 240)
        pdf.multi_cell(w=90,
                       h=6,
                       txt="_____________________________________\n"
                           "JOÃO ALEXANDRE\nPESCHANSKI\nPesquisador associado\ndo CEPID NeuroMat",
                       border=0,
                       align='C')
        pdf.cell(w=0, h=5, ln=1)

        # Generate the file
        file = pdf.output(dest='S').encode('latin-1')

        response = make_response(file)
        response.headers.set('Content-Disposition', 'inline',
                             filename='IJC_Inscrição_' + name.replace(" ", "_") + '.pdf')
        response.headers.set('Content-Type', 'application/pdf')
        return response
    else:
        return redirect(url_for('home'))


# Validar documentos
@app.route('/validate', methods=['POST', 'GET'])
def validate_document():
    """
    This function verifies the validation of documents of the course

    :return: A message validating or denying a hash of a document
    """
    username = get_username()

    if request.method == 'POST':
        hash_to_be_checked = request.form["hash"]

        if hash_to_be_checked:
            users = Users.query.all()
            hashs_sub = [
                hashlib.sha1(bytes("Subscription " + user.username + str(user.date_modified), 'utf-8')).hexdigest()
                for user in users]
            hashs_certificate = [
                hashlib.sha1(bytes("Certificate " + user.username + str(user.date_modified), 'utf-8')).hexdigest()
                for user in users]

            if hash_to_be_checked in hashs_sub or hash_to_be_checked in hashs_certificate:
                message = True
            else:
                message = False

            return render_template('validation.html', username=username, message=message, success=True)
        else:
            return render_template('validation.html', username=username)
    else:
        return render_template('validation.html', username=username)


# Baixar índice
@app.route('/index', methods=['GET'])
def course_index():
    base_url = "https://pt.wikiversity.org/api/rest_v1/page/pdf/Programa_de_Introdução_ao_Jornalismo_Científico"

    response = make_response(requests.get(base_url).content)
    response.headers.set('Content-Disposition', 'attachment',
                         filename='IJC_Programa.pdf')
    response.headers.set('Content-Type', 'application/pdf')
    return response


# Gerar certificado
@app.route('/generate_certificate', methods=['GET'])
def generate_certificate():
    """
    This function generates a pdf file with the certificate for the course

    :return: A pdf file with the certificate
    """
    username = get_username()

    user = Users.query.filter_by(username=username).first()
    if username and user:
        if user.can_download_certificate == ";".join(["T" for i in range(app.config["NUMBER_OF_MODULES"])]):
            # Create page
            pdf = CertificationPDF(orientation='L', unit='mm', format='A4')
            pdf.add_page()
            pdf.set_text_color(0, 46, 75)

            #######################################################################################################
            # Header
            #######################################################################################################
            pdf.set_y(20)                          # Start the letter text at the 10x42mm point

            pdf.add_font('Merriweather', '', os.path.join(app.static_folder, 'fonts/Merriweather-Regular.ttf'), uni=True)
            pdf.add_font('Merriweather-Bold', '', os.path.join(app.static_folder, 'fonts/Merriweather-Bold.ttf'), uni=True)
            pdf.set_font('Merriweather', '', 37)               # Text of the body in Times New Roman, regular, 13 pt

            locale.setlocale(locale.LC_TIME, "pt_BR")   # Setting the language to portuguese for the date
            pdf.cell(w=0, h=10, border=0, ln=1, align='C', txt='CERTIFICADO')

            pdf.set_font('Merriweather', '', 14.5)
            pdf.cell(w=0, h=10, border=0, ln=1, align='C', txt='Concedemos este certificado a')
            pdf.cell(w=0, h=10, ln=1)                  # New line

            #######################################################################################################
            # User name
            #######################################################################################################
            user = Users.query.filter_by(username=username).first()
            name = user.full_name                                       # User full name
            pdf.set_font('Merriweather', '', 35)
            name_size = pdf.get_string_width(name)

            if name_size > 287:
                # Try to eliminate the prepositions
                name_split = [name_part for name_part in name.split(' ') if not name_part.islower()]
                # There's a first and last names and at least one middle name
                if len(name_split) > 2:
                    first_name = name_split[0]
                    last_name = name_split[-1]
                    middle_names = [md_name[0]+'.' for md_name in name_split[1:-1]]
                    name = first_name + ' ' + ' '.join(middle_names) + ' ' + last_name
                    name_size = pdf.get_string_width(name)

                # Even abbreviating, there is still the possibility that the name is too big, so
                # we need to adjust it to the proper size
                if name_size > 287:
                    pdf.set_font('Merriweather', '', math.floor(287 * 35 / name_size))

            pdf.cell(w=0, h=10, border=0, ln=1, align='C', txt=name)
            pdf.cell(w=0, h=10, ln=1)  # New line

            #######################################################################################################
            # por ter completado as leituras e as 6 tarefas do curso online
            #######################################################################################################
            pdf.set_font('Merriweather', '', 14.5)
            pdf.cell(w=0, h=10, border=0, ln=1, align='C', txt='por ter completado as leituras e as ' +
                                                               str(app.config["NUMBER_OF_MODULES"]) +
                                                               ' tarefas do curso online')

            #######################################################################################################
            # Introdução ao Jornalismo Científico
            #######################################################################################################
            pdf.set_font('Merriweather-Bold', '', 21)
            pdf.cell(w=0, h=10, border=0, ln=1, align='C', txt='Introdução ao Jornalismo Científico')
            pdf.cell(w=0, h=8, ln=1)  # New line

            #######################################################################################################
            # Logo NeuroMat
            #######################################################################################################
            pdf.set_font('Merriweather', '', 12.5)
            pdf.set_x(50)
            y_production = pdf.get_y()
            pdf.cell(w=20, h=10, border=0, ln=0, align='L', txt='Produção:')
            _y_logos = pdf.get_y()
            pdf.image(os.path.join(app.static_folder, 'neuromat.png'), x=78, y=y_production+0.6, h=8.5)

            #######################################################################################################
            # Logo FAPESP and WMB
            #######################################################################################################
            pdf.set_xy(155, y_production)
            pdf.cell(w=20, h=10, border=0, ln=1, align='L', txt='Apoio:')
            pdf.image(os.path.join(app.static_folder, 'fapesp.png'), x=175, y=y_production+1.1, h=7)
            pdf.image(os.path.join(app.static_folder, 'wmb.png'), x=215, y=y_production-1.1, h=13)

            pdf.cell(w=0, h=5, ln=1)  # New line

            #######################################################################################################
            # Footer
            #######################################################################################################
            y_signature = pdf.get_y()                   # Register the "y" position, so the signatures are aligned

            # Fernando da Paixão signature
            pdf.image(os.path.join(app.static_folder, 'fpaixao.png'), x=75, y=y_signature, w=35, h=16)
            pdf.set_xy(50, y_signature+6)
            pdf.multi_cell(w=90,
                           h=6.5,
                           txt="______________________\n"
                               "FERNANDO JORGE DA\nPAIXÃO FILHO\n\nCoordenador da equipe de\ndifusão do CEPID NeuroMat",
                           border=0,
                           align='C')

            # João Alexandre Peschanski signature
            pdf.image(os.path.join(app.static_folder, 'jap.png'), x=180, y=y_signature+2, w=35, h=16)
            pdf.set_xy(155, y_signature+6)
            pdf.multi_cell(w=90,
                           h=6.5,
                           txt="______________________\n"
                               "JOÃO ALEXANDRE\nPESCHANSKI\n\nPesquisador associado\ndo CEPID NeuroMat",
                           border=0,
                           align='C')
            pdf.cell(w=0, h=10, ln=1)  # New line
            pdf.set_font('Merriweather', '', 10.5)

            # Text
            pdf.set_x(25)
            pdf.multi_cell(w=247, h=10, border=0, align='C', txt='O curso de Introdução ao Jornalismo Científico não tem um '
                                                                 'controle de registros, as leituras e tarefas são de acesso '
                                                                 'livre. Este certificado, portanto, não é reconhecido como '
                                                                 'um diploma oficial. O curso totaliza para sua realização '
                                                                 'noventa horas.')

            # Generate the file
            file = pdf.output(dest='S').encode('latin-1')

            response = make_response(file)
            response.headers.set('Content-Disposition', 'attachment',
                                 filename='IJC_Certificado_' + name.replace(" ", "_") + '.pdf')
            response.headers.set('Content-Type', 'application/pdf')
            return response
        else:
            return redirect(url_for('certificate'))
    else:
        return redirect(url_for('home'))


# Gerar anexos
@app.route('/generate_attachment', methods=['GET'])
def generate_attachment():
    username = get_username()

    base_url = "https://pt.wikiversity.org/api/rest_v1/page/pdf/"
    prefix_course = 'Introdução_ao_Jornalismo_Científico%2F'
    pages = ["Metodologia_e_Filosofia_da_Ciência%2FAtividade%2F",
             "História_da_Ciência_e_da_Tecnologia%2FAtividade%2F",
             "Ética_da_Ciência%2FAtividade%2F",
             "Temas_Centrais_da_Ciência_Contemporânea%2FAtividade%2F",
             "Modos_de_Organização_e_Financiamento_dos_Sistemas_de_Pesquisa,_no_Brasil_e_no_Exterior%2FAtividade%2F",
             "Mídias,_Linguagens_e_Prática_do_Jornalismo_Científico%2FAtividade%2F"]

    user = Users.query.filter_by(username=username).first()

    if user and user.can_download_certificate == ";".join(["T" for i in range(app.config["NUMBER_OF_MODULES"])]):
        try:
            responses = []
            for page in pages:
                responses.append(PyPDF2.PdfFileReader(io.BytesIO(requests.get(base_url + prefix_course + page + user.username).content)))
            output = io.BytesIO()
            writer = PyPDF2.PdfFileWriter()
            for response in responses:
                n = response.getNumPages()
                for i in range(n):
                    writer.addPage(response.getPage(i))

            writer.write(output)
            result = Response(output.getvalue(), mimetype="application/pdf")
            result.headers.set('Content-Disposition', 'attachment',
                               filename='IJC_Anexos_' + user.full_name.replace(' ', '_') + '.pdf')
            result.headers.set('Content-Type', 'application/pdf')
            return result
        except:
            return redirect(url_for('certificate'))
    else:
        return redirect(url_for('certificate'))


# Gerenciar atividades
@app.route('/certificate', methods=['GET'])
def certificate():
    username = get_username()

    if request.method == 'GET':
        if username in app.config['COORDINATORS_USERNAMES']:
            users = Users.query.order_by(Users.date_created.desc())
            return render_template('certificate.html',
                                   aulas=MODULES,
                                   username=username,
                                   users=users,
                                   coordinator=True)
        else:
            users = Users.query.filter_by(username=username)

            if users.first():
                can_download_certificate = all(x == "T" for x in users.first().can_download_certificate.split(";"))
            else:
                return redirect(url_for('subscription'))
            return render_template('certificate.html',
                                   aulas=MODULES,
                                   username=username,
                                   users=users,
                                   can_download_certificate=can_download_certificate)
    else:
        return redirect(url_for('home'))

@app.route('/certificate/module_timestamps/<user_username>', methods=['GET'])
def certificate_module_timestamps(user_username):
    username = get_username()

    if username in app.config['COORDINATORS_USERNAMES']:
        users = Users.query.filter_by(username=user_username)
    else:
        users = Users.query.filter_by(username=username)

    if users.first():
        INDEX_TO_SKIP = 1
        user = users.first()
        titles = []
        modules_to_check = list(MODULES)
        modules_to_check.pop(INDEX_TO_SKIP) # remove outreach dashboard
        for m in modules_to_check:
            title_wiki = m.split("https://pt.wikiversity.org/wiki/")[-1]
            titles.append(f"{title_wiki}{user.username}")
        params={
            "format": "json",
            "action": "query",
            "prop": "revisions",
            "rvslots": "*",
            "rvprop": "timestamp|user",
            "titles": "|".join(titles),
        }
        result = requests.get("https://pt.wikiversity.org/w/api.php", params=params, headers={"User-Agent": USER_AGENT}).json()
        timestamps = []
        api_pages = result["query"]["pages"].values()
        for original_title in titles:
            use_title = original_title
            for normalized in result["query"].get("normalized", []):
                if original_title == normalized["from"]:
                    use_title = normalized["to"]
            found = False
            for api_page in api_pages:
                if use_title == api_page.get("title"):
                    timestamps.append(api_page.get("revisions", [{}])[-1].get("timestamp", None))
                    found = True
            if not found:
                timestamps.append(None)
        timestamps.insert(INDEX_TO_SKIP, None)
        return render_template('certificate_module_timestamps.html', user=user, timestamps=timestamps)
    else:
        return render_template('certificate_module_timestamps.html', user=None, timestamps=[])

# Gerenciar atividades
@app.route('/certificate/requested', methods=['GET'])
def certificate_only_requested():
    username = get_username()

    if username in app.config['COORDINATORS_USERNAMES']:
        if request.method == 'GET':
            users = Users.query.filter_by(solicited_certificate=True).order_by(Users.date_created.desc())
            return render_template('certificate.html',
                                   aulas=MODULES,
                                   username=username,
                                   users=users,
                                   coordinator=True)
    else:
        return redirect(url_for('certificate'))


# Solicitar certificado
@app.route('/solicit_certificate', methods=['GET'])
def solicit_certificate():
    username = get_username()

    user_soliciting = Users.query.filter_by(username=username).first()
    if username and user_soliciting and user_soliciting.can_download_certificate != "T;T;T;T;T;T" and not user_soliciting.solicited_certificate:
        user_soliciting.solicited_certificate = True

        status_activities = ";".join(
            ["NP" if x == "F" else x for x in user_soliciting.can_download_certificate.split(";")])
        user_soliciting.can_download_certificate = status_activities

        try:
            db.session.commit()
            ask_coordinator_for_certificate_email(user_soliciting.username, user_soliciting.full_name)
            return redirect(url_for('certificate'))
        except:
            return 'Ocorreu um erro!'
    else:
        return redirect(url_for('certificate'))


# Rejeitar pedido de certificação (atividades pendentes)
@app.route('/deny_solicitation/<user_username>', methods=['GET'])
def deny_solicitation_for_certificate(user_username):
    username = get_username()

    if username in app.config['COORDINATORS_USERNAMES']:
        user_denied = Users.query.filter_by(username=user_username).first()
        if user_username and user_denied:
            user_denied.solicited_certificate = False
            try:
                db.session.commit()
                return redirect(url_for('certificate'))
            except:
                return 'Ocorreu um erro!'
    else:
        return redirect(url_for('certificate'))


# Aprovar certificação sem pedido
@app.route('/approve_certification_without_request/<user_username>', methods=['GET'])
def approve_certification_without_request(user_username):
    username = get_username()

    if username in app.config['COORDINATORS_USERNAMES']:
        user_approved = Users.query.filter_by(username=user_username).first()
        if user_username and user_approved:
            user_approved.solicited_certificate = True
            user_approved.can_download_certificate = ";".join(["T" for i in range(app.config["NUMBER_OF_MODULES"])])
            try:
                db.session.commit()
                return redirect(url_for('certificate'))
            except:
                return 'Ocorreu um erro!'
    else:
        return redirect(url_for('certificate'))


# Aprovar uma atividade
@app.route('/approve_certification/<user>/<module_activity>', methods=['GET'])
def approve_certification(user, module_activity):
    username = get_username()

    if username in app.config['COORDINATORS_USERNAMES'] and int(module_activity) >= 1:
        user_to_be_approved = Users.query.filter_by(username=user).first()

        user_modules_activities = user_to_be_approved.can_download_certificate.split(";")
        user_modules_activities[int(module_activity)-1] = "T"
        user_to_be_approved.can_download_certificate = ";".join(user_modules_activities)
        try:
            db.session.commit()
            return redirect(url_for('certificate'))
        except:
            return 'Ocorreu um erro!'
    else:
        return redirect(url_for('certificate'))


# Rejeitar uma atividade
@app.route('/deny_certification/<user>/<module_activity>', methods=['GET'])
def deny_certification(user, module_activity):
    username = get_username()

    if username in app.config['COORDINATORS_USERNAMES']:
        user_to_be_approved = Users.query.filter_by(username=user).first()

        user_modules_activities = user_to_be_approved.can_download_certificate.split(";")
        user_modules_activities[int(module_activity)-1] = "F"
        user_to_be_approved.can_download_certificate = ";".join(user_modules_activities)
        try:
            db.session.commit()
            return redirect(url_for('certificate'))
        except:
            return 'Ocorreu um erro!'
    else:
        return redirect(url_for('certificate'))

# Cancela/reseta aprovação ou rejeição uma atividade
@app.route('/reset_certification/<user>/<module_activity>', methods=['GET'])
def reset_certification(user, module_activity):
    username = get_username()
    if username in app.config['COORDINATORS_USERNAMES']:
        user_to_be_approved = Users.query.filter_by(username=user).first()
        user_modules_activities = user_to_be_approved.can_download_certificate.split(";")
        user_modules_activities[int(module_activity)-1] = "NP"
        user_to_be_approved.can_download_certificate = ";".join(user_modules_activities)
        try:
            db.session.commit()
            return redirect(url_for('certificate'))
        except:
            return 'Ocorreu um erro!'
    else:
        return redirect(url_for('certificate'))

@app.route('/wikipedia_edit_count/<user_username>', methods=['GET'])
def wikipedia_edit_count(user_username):
    username = get_username()
    if username in app.config['COORDINATORS_USERNAMES']:
        user = Users.query.filter_by(username=user_username).first()
    else:
        user = Users.query.filter_by(username=username).first()
    if user:
        username = user.username
        params={
            "format": "json",
            "action": "query",
            "list": "usercontribs",
            "ucuser": username,
            "uclimit": "max",
            "ucprop": "ids|title|timestamp|sizediff|flags|tags",
        }
        result = requests.get("https://pt.wikipedia.org/w/api.php", params=params, headers={"User-Agent": USER_AGENT}).json()
        edits = result["query"]["usercontribs"]
        total_diff = 0
        for edit in edits:
            if edit["ns"] != 0:
                edit["ignored"] = "namespace"
                continue
            if "mw-reverted" in edit["tags"]:
                edit["ignored"] = "reverted"
                continue
            sizediff = edit["sizediff"]
            if sizediff > 0:
                total_diff += sizediff
        return render_template("wikipedia_edit_count.html", username=username, edits=edits, total_diff=total_diff)
    else:
        return render_template("wikipedia_edit_count.html")


def get_revision_ids(data):
    return_list = {}
    for elem in data['query']['pages']:
        title = data['query']['pages'][elem]['title']
        if 'revisions' in data['query']['pages'][elem]:
            revid = str(data['query']['pages'][elem]['revisions'][0]['revid'])
            link = 'https://pt.wikiversity.org/w/index.php?title='+title+'&oldid='+revid
            return_list[title] = link, True
        else:
            return_list[title] = 'https://pt.wikiversity.org/w/index.php?title='+title+'&action=edit&redlink=1', False
    return return_list


def get_content(data):
    return_list = {}
    for elem in data['query']['pages']:
        title = data['query']['pages'][elem]['title']
        if 'revisions' in data['query']['pages'][elem]:
            content = str(data['query']['pages'][elem]['revisions'][0]['*'])
            return_list[title] = content
        else:
            return_list[title] = ''
    return return_list


# Enviar email
def ask_coordinator_for_certificate_email(username, fullname):
    email_sender = app.config["GMAIL_EMAIL"]
    email_password = app.config["GMAIL_PASSWORD"]
    email_receiver = app.config["GMAIL_COORDINATOR_EMAIL"]

    subject = "{fullname} ({username}) está solicitando um certificado do curso de Introdução ao Jornalismo Científico"
    body = """Olá, {coordinator},<br><br>O(A) estudante {fullname}, cujo nome de usuário é {username} está solicitando que suas atividades do curso <b>Introdução ao Jornalismo Científico</b> sejam avaliadas e lhe seja garantido o certificado de conclusão do curso.<br><br>Você pode verificar este(a) e outros(as) estudantes com avaliações pendentes em {url}.<br><br><b>Introdução ao Jornalismo Científico</b><br>Solicitações de certificados | <a href="{url_home}">ijc.toolforge.org</a>"""

    em = EmailMessage()
    em["From"] = formataddr((str(Header(app.config["GMAIL_EMAIL_HEADER"], 'utf-8')), email_sender))
    em["To"] = ", ".join(email_receiver)
    em["Subject"] = subject.format(fullname=fullname, username=username)
    formatted_body = body.format(fullname=fullname,
                                 username=username,
                                 url=url_for("certificate_only_requested", _external=True),
                                 url_home=url_for("home", _external=True),
                                 coordinator=" e ".join([", ".join(app.config["COORDINATORS_USERNAMES"][:-1]), app.config["COORDINATORS_USERNAMES"][-1]]))
    em.set_content(MIMEText(formatted_body, "html"))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())


if __name__ == '__main__':
    app.run()

