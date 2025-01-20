from flask import Flask, render_template, url_for, redirect, session, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.secret_key = "your_secret_key"


##Configure SQL Alchemy (Sets up the file)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


##Database Model (How the db will track info. | What a single row on the db will look like)
class User(db.Model):
    ##Class Vars.
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    passwordHash = db.Column(db.String(150), nullable=False)

    def setPassword(self, password):
        self.passwordHash = generate_password_hash(password)

        
    def checkPassword(self, password):
        return check_password_hash(self.passwordHash, password)
        



@app.route('/')
def index():
    if "username" in session:
        return redirect(url_for('dashboard'))

    return render_template('index.html')


####
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.checkPassword(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html')

    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template("index.html")

        user = User.query.filter_by(username=username).first()

        if user:
            return render_template("index.html")

        newUser = User(username=username)
        newUser.setPassword(password)
        db.session.add(newUser)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        return render_template("index.html")


#Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('index'))
#####

@app.route('/about')
def about():
    return render_template('about.html')

# Processing For Invalid URL
@app.route('/<userInput>')
def reset(userInput):
    return redirect(url_for('index'))


if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            print("Database Created")
        except: 
            print("Database not created")

    app.run(debug=True)
