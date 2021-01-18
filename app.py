#! /usr/bin/python
# -*- coding:utf-8 -*-
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, jsonify, send_file
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, RadioField, BooleanField
from sqlalchemy import create_engine, MetaData, Table
from werkzeug.utils import secure_filename
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from datetime import datetime
from functools import wraps
import zipfile, os

# Initialise app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
DOSSIER_UPS = 'E:/Projet1/Projet/Documents/'

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

@app.route('/h') 
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
@app.route('/', methods=['GET', 'POST'])
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

def folder_or_file(doc): # Test if doc is a folder a file
    return os.path.isdir(doc) # os.path.isfile(doc)

def Size(path):
    unity = { '0': 'o', '1': 'ko', '2': 'Mo', '3': 'Go', '4': 'To' }
    sizes, num = 0, 0
    if folder_or_file(path):
        for root, dirs, files in os.walk(path, 'topdown'):
            for file in files: sizes += os.path.getsize(os.path.join(root, file))
    else: sizes =  os.path.getsize(path)
    size = sizes
    while size > 0.9:
        size = size/1024
        num += 1
    if num > 0:
        size = str(sizes/1024**(num-1))
        point = size.find('.') 
        size = size[: point + 3] + ' ' + unity[str(num-1)]
    else:
        size = str(sizes/1024**num)
        point = size.find('.') 
        size = size[: point + 3] + ' ' + unity[str(num)]
    return size

def DateConverter(path):
    date =  os.path.getmtime(path)
    date = str(datetime.fromtimestamp(date))
    point = date.find('.')
    if point != -1: return date[: point]
    else: return date

# Dashboard
@app.route('/dashboard', methods=["GET","POST"])
@app.route('/dashboard/<folder>', methods=["GET","POST"])
@is_logged_in
def dashboard(folder=None):
    folders, files, folderLink, filesize, fileLastModified, foldersize, folderLastModified = [], [], [], [], [], [], []
    folderPath, folderPath1, fol = '', '', ''
    if folder: DOSSIER_UP = os.path.join(DOSSIER_UPS, folder)
    else: DOSSIER_UP = DOSSIER_UPS
    for doc in os.listdir(DOSSIER_UP):
        if folder_or_file(os.path.join(DOSSIER_UP, doc)):
            if folder: 
                folderLink.append(os.path.join(folder, doc))
                folders.append(doc)
            else: 
                folderLink.append(doc)
                folders.append(doc)
            foldersize.append(Size(os.path.join(DOSSIER_UP, doc)))
            folderLastModified.append(DateConverter(os.path.join(DOSSIER_UP, doc)))
        else: 
            filesize.append(Size(os.path.join(DOSSIER_UP, doc)))
            fileLastModified.append(DateConverter(os.path.join(DOSSIER_UP, doc)))
            files.append(doc)                    # [file for file in os.listdir(DOSSIER_UPS) if extension_ok(file)] # la liste des images dans le dossier
    if folder: 
        folderPath = folder.split('\\')
        folderPath1 = folder[:folder.find(folderPath[-1])]
        fol=folder
    return render_template('dashboard.html', fol=fol, folderPath1=folderPath1, folderPath=folderPath, folderLink=folderLink, folders=folders, 
    files=files, folderLen=len(folders), fileLen=len(files), filesize=filesize, fileLastModified=fileLastModified, foldersize=foldersize, folderLastModified=folderLastModified)

# Edit or open a file by clicking on a file
@app.route('/upped/<filePath>')
@is_logged_in
def upped(filePath):
    if filePath.find('&&') != -1: filename = "/".join(filePath.split('&&'))
    else: filename = filePath
    FilePath = os.path.join(DOSSIER_UPS, filename)
    os.popen('start ' + FilePath)
    file =  os.path.dirname(filename)
    if file: return redirect(url_for('dashboard', folder=file))
    else: return redirect(url_for('dashboard'))
    
# Upload file
@app.route('/upload/<folder>', methods=['GET', 'POST'])
@is_logged_in
def upload(folder=None):
    if request.method == 'POST':
        f = request.files['fic']
        if f: # on vérifie qu'un fichier a bien été envoyé
            nom = secure_filename(f.filename)
            FilePath = os.path.join(DOSSIER_UPS, folder)
            f.save(os.path.join(FilePath, nom))
            return redirect(url_for('dashboard', folder=folder))
        else:
            flash(u"Vous n'avez pas selectionné un fichier !", 'error')        
    return render_template('dashboard.html')

# Create Folder and Rename file
@app.route('/create_rename', methods=['GET', 'POST'])
def create_rename():
    # Rename file
    if 'filename' in request.form.keys():
        Url = request.form['Path']
        Url1 = Url.split('/')
        file, ext = os.path.splitext(request.form['filename'])
        if Url1[1] == '':
            OldName = os.path.join(DOSSIER_UPS, request.form['filename'])
            NewName = os.path.join(DOSSIER_UPS, request.form['name'] + ext)
        else:
            if file != '' and ext != '':
                Url = Url[Url.find(Url1[1]):]
                OldName = os.path.join(DOSSIER_UPS, Url + request.form['filename'])
                NewName = os.path.join(DOSSIER_UPS, Url + request.form['name'] + ext)
            else:
                Url = Url[Url.find(Url1[1]):]
                OldName = os.path.join(DOSSIER_UPS, Url + request.form['filename'])
                NewName = os.path.join(DOSSIER_UPS, Url + request.form['name'])
        os.rename(OldName, NewName)
    else:
        # Create a Folder
        Url = request.form['Path']
        Url1 = Url.split('/')
        if Url1[1] != '':
            Url = Url[Url.find(Url1[1]):]
            Path = os.path.join(DOSSIER_UPS, Url + request.form['name'])
        else:
            Path = os.path.join(DOSSIER_UPS, request.form['name'])
        if(not os.path.exists(Path)):
            os.mkdir(Path)
        else: flash('This file already exist','error')
    
# Edit, Dowload or Delete Files or Folders
@app.route('/edit_delete_download', methods=['GET', 'POST'])
def edit_delete_download():
    print("Path = ", request.form['Path'], request.form['filename'])
    # Edit one or more files by checking
    if request.form['work'] == 'edit':
        Url = request.form['Path']
        Url1 = Url.split('/')
        if Url1[1] != '':
            Url = Url[Url.find(Url1[1]):]
            for file in request.form['filename'].split('/')[:-1]:
                if file.find(' ') != -1: file = '"' + file + '"'
                Path = os.path.join(DOSSIER_UPS, Url + file)
                os.popen('start ' + Path)
        else:
            for file in request.form['filename'].split('/')[:-1]:
                if file.find(' ') != -1: file = '"' + file + '"'
                Path = os.path.join(DOSSIER_UPS, file)
                os.popen('start ' + Path)
    elif request.form['work'] == 'delete':
        Url = request.form['Path']
        Url1 = Url.split('/')
        if Url1[1] != '':
            Url = Url[Url.find(Url1[1]):]
            for file in request.form['filename'].split('/')[:-1]:
                if file.find(' ') != -1: file = '"' + file + '"'
                Path = os.path.join(DOSSIER_UPS, Url + file)
                Path = Path.replace('/', '\\')
                os.popen('DEL ' + Path)
        else:
            for file in request.form['filename'].split('/')[:-1]:
                if file.find(' ') != -1: file = '"' + file + '"'
                Path = os.path.join(DOSSIER_UPS, file)
                os.popen('DEL ' + Path)

@app.route('/up')
@app.route('/up/view/<nom>')
def download(nom):
    word = {}
    folderDirectory = "/".join(nom.split("&&")[:-1]) + '/'
    noms = nom.split("&&")[-1]
    filename = noms.split('&')[:-1]
    print("nom = ", folderDirectory, filename)
    if len(filename) == 1:
        if folderDirectory == '/': word['choice'] = send_file(DOSSIER_UPS + filename[0], as_attachment=True)
        else: word['choice'] = send_file(DOSSIER_UPS + folderDirectory + filename[0], as_attachment=True)
    else:
        destination = os.path.dirname(os.path.dirname(DOSSIER_UPS))
        destination = destination.replace('/', '\\') + '\\' + "Docu"
        destidrive, sourcedrive = [], []
        for i in filename:
            if folderDirectory == '/': folderDirectori = i
            else: folderDirectori = folderDirectory + i
            if folder_or_file(DOSSIER_UPS + folderDirectori):
                foldername = DOSSIER_UPS + folderDirectori
                foldername = foldername.replace('/', '\\')
                for root, dirs, files in os.walk(foldername, 'topdown'):
                    for file in files:
                        destidrive.append(os.path.join(root.replace(DOSSIER_UPS.replace('/', '\\')[:-1], destination), file))
                        sourcedrive.append(root + '\\' + file)
            else:
                sourcedrive.append(DOSSIER_UPS.replace('/', '\\') + folderDirectori.replace('/', '\\'))
                destidrive.append(destination + '\\' + i)
        # Zip file Initilization
        zipfolder = zipfile.ZipFile("file.zip", mode='w', compression=zipfile.ZIP_STORED, allowZip64=True) # Compression type. we can also use instead of ZIP_STORED, ZIP_DEFLATED, ZIP_BZIP2, ZIP_LZMA
        # Zip all the files which are inside in the folder
        for i in range(len(destidrive)):
            zipfolder.write(sourcedrive[i], destidrive[i])
        zipfolder.close()
        send_file("file.zip", mimetype = 'zip', attachment_filename='file.zip', as_attachment=True)
        os.remove("file.zip")
        return redirect(url_for('dashboard', folder=folderDirectory[:-1]))

# Run Server
if __name__ == '__main__':
    app.secret_key = "secret_key1234"
    app.run(debug=True)
    # app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)