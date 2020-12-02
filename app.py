#! /usr/bin/python
# -*- coding:utf-8 -*-
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, jsonify, send_file
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, RadioField, BooleanField
from sqlalchemy import create_engine, MetaData, Table
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from datetime import datetime
from functools import wraps
import os

# Initialise app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
DOSSIER_UPS = 'E:/Projet1/Projet Test/Images/'

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialise database
db = SQLAlchemy(app)
# Initialise marshmallow
ma = Marshmallow(app)

# User Identification Class/Model
class UserIdent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    UserName = db.Column(db.String(100))
    FirstName = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    DateCreat = db.Column(db.String(20))

    def __init__(self, UserName, FirstName, email, password, DateCreat):
        self.UserName = UserName
        self.FirstName = FirstName
        self.email = email
        self.password = password
        self.DateCreat = DateCreat

# Folder Identification Class/Model
class FolderIdent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    FolderName = db.Column(db.String(50))
    idFolderParent = db.Column(db.Integer)
    TypeFile = db.Column(db.String(20))
    DateCreat = db.Column(db.String(20))
    DateModify = db.Column(db.String(20))

    def __init__(self, FolderName, idFolderParent, TypeFile, DateCreat, DateModify):
        self.FolderName = FolderName
        self.idFolderParent = idFolderParent
        self.TypeFile = TypeFile
        self.DateCreat = DateCreat
        self.DateModify = DateModify

# File Identification Class/Model
class FileIdent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    FileName = db.Column(db.String(50))
    idUser = db.Column(db.Integer)
    idFolder = db.Column(db.Integer)
    TypeFile = db.Column(db.String(20))
    DateCreat = db.Column(db.String(20))

    def __init__(self, FileName, idUser, idFolder, TypeFile, DateCreat):
        self.FileName = FileName
        self.idUser = idUser
        self.idFolder = idFolder
        self.TypeFile = TypeFile
        self.DateCreat = DateCreat

# Message Identification Class/Model
class SmsIdent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    idSender = db.Column(db.Integer)
    idReceiver = db.Column(db.Integer)
    idFile = db.Column(db.Integer)
    Text = db.Column(db.String(250))
    DateCreat = db.Column(db.String(20))

    def __init__(self, idSender, idReceiver, idFile, Text, DateCreat):
        self.idSender = idSender
        self.idReceiver = idReceiver
        self.idFile = idFile
        self.Text = Text
        self.DateCreat = DateCreat

# Identification Schema
class UserIdentSchema(ma.Schema):
    class Meta:
        fields = ('id', 'UserName', 'FirstName', 'email', 'password', 'DateCreat')

class FolderIdentSchema(ma.Schema):
    class Meta:
        fields = ('id', 'FolderName', 'idFolderParent', 'TypeFile', 'DateCreat', 'DateModify')

class FileIdentSchema(ma.Schema):
    class Meta:
        fields = ('id', 'FileName', 'idUser', 'idFolder', 'TypeFile', 'DateCreat')

class SmsIdentSchema(ma.Schema):
    class Meta:
        fields = ('id', 'idSender', 'idReceiver', 'idFile', 'Text', 'DateCreat')

# Initialise a UserIdent
UserIdent_schema = UserIdentSchema()
UserIdents_schema = UserIdentSchema(many=True)

# Initialise a FolderIdent
FolderIdent_schema = FolderIdentSchema()
FolderIdents_schema = FolderIdentSchema(many=True)

# Initialise a FileIdent
FileIdent_schema = FileIdentSchema()
FileIdents_schema = FileIdentSchema(many=True)

# Initialise a SmsIdent
SmsIdent_schema = SmsIdentSchema()
SmsIdents_schema = SmsIdentSchema(many=True)

now = datetime.now()
date = now.strftime("%Y/%m/%d %H:%M:%S")

@app.route('/') 
def index():
    session.clear()
    return render_template('Home.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Register Form Class
class RegisterForm(Form):
    UserName = StringField(u'UserName', validators=[validators.DataRequired(), validators.length(min=1, max=50)])
    FirstName = StringField(u'Full Name', validators=[validators.DataRequired(), validators.length(min=1, max=50)])
    email = StringField(u'E-mail', validators=[validators.DataRequired(), validators.length(min=10, max=50)])
    password = PasswordField(u'Password', [
         validators.DataRequired(),
         validators.EqualTo('confirm', message='Passwords do not match')
     ])
    confirm = PasswordField('Confirm Password')
    hasAgreed = BooleanField(u'By clicking here,', validators=[validators.DataRequired()])

# User register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        UserName = form.UserName.data
        FirstName = form.FirstName.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))
        new_user = UserIdent(UserName, FirstName, email, password, date)
        db.session.add(new_user)
        db.session.commit()
        session['logged_in'] = True
        session['username'] = UserName
        #flash('You are now registered and can log in', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        name = request.form['username']
        password_candidate = request.form['password']
    
        # Get user by username
        Result = {}
        for user in UserIdent.query.all():
            Result[user.UserName] = user.password
        if name in Result.keys():
            # Compare Password
            password = Result[name]
            if sha256_crypt.verify(password_candidate, password):
                # passed 
                app.logger.info('PASSWORD MATCHED')
                session['logged_in'] = True
                session['username'] = name

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.info('PASSWORD NOT MATCHED')
                error = 'Invalid login'
                return render_template('login.html', error=error)
        else:
            app.logger.info('NO USER')
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

def extension_ok(nomfic):
    """ Renvoie True si le fichier possède une extension d'image valide. """
    return '.' in nomfic and nomfic.rsplit('.', 1)[1] in ('png', 'jpg', 'JPG', 'jpeg', 'gif', 'bmp')

# Dashboard
@app.route('/dashboard', methods=["GET","POST"])
@is_logged_in
def dashboard():
    images = [img for img in os.listdir(DOSSIER_UPS) if extension_ok(img)] # la liste des images dans le dossier
    return render_template('dashboard.html', images=images)

@app.route('/up/view/<nom>')
def upped(nom):
    #nom = secure_filename(nom)
    if os.path.isfile(DOSSIER_UPS + nom): # si le fichier existe
        return send_file(DOSSIER_UPS + nom, as_attachment=True) #  on l'envoie
    else:
        flash(u'Fichier {nom} inexistant.'.format(nom=nom), 'error')
        return redirect(url_for('liste_upped')) # sinon on redirige vers la liste des images, avec un message d'erreur

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if request.form['pw'] == 'up': # on vérifie que le mot de passe est bon
            f = request.files['fic']
            if f: # on vérifie qu'un fichier a bien été envoyé
                if extension_ok(f.filename): # on vérifie que son extension est valide
                    nom = f.filename # secure_filename(f.filename)
                    f.save(DOSSIER_UPS + nom)
                    flash(u'Image envoyée ! Voici <a href="{lien}">son lien</a>'.format(lien=url_for('upped', nom=nom)), 'error')
                    return redirect(url_for('liste_upped'))
                else:
                    flash(u'Ce fichier ne porte pas une extension autorisée !', 'error')
            else:
                flash(u'Vous avez oublié le fichier !', 'error')
        else:
            flash(u'Mot de passe incorrect', 'success')
    return render_template('up_up.html')
# Run Server
if __name__ == '__main__':
    app.secret_key = "secret_key1234"
    app.run(debug=True)