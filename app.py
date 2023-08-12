from flask_sqlalchemy import SQLAlchemy
from flask import render_template, request,Flask,redirect,url_for,session,jsonify
from flask_login import LoginManager,login_user,login_required,logout_user,current_user
from datetime import datetime
from matplotlib import pyplot as plt
from matplotlib.ticker import MaxNLocator
from matplotlib.dates import DateFormatter
import jinja2
import smtplib
import uuid


#app initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quantified_self_database.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db = SQLAlchemy(app)
app.app_context().push()
app.config['SECRET_KEY']='myappquantified'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='/notfound/Unauthorized'
#database import
from database import db,User,Form


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))




@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username')
        password=request.form.get('password')
        try:
            user=User.query.filter(User.username==username,User.password==password).one()
        except:
            return render_template('login.html',error='incorrect password or username')
        if not current_user.is_active:
            login_user(user)
    if current_user.is_active:
        return main()
    else:
        return render_template('login.html')



@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method=='POST':
        username=request.form.get('username')
        email = request.form['email']
        password=request.form.get('password')
        if username not in [i.username for i in User.query.all()]:
            if len(password) >= 8:
                has_capital = False
                has_digit = False
                
                for letter in password:
                    if letter.isupper():
                        has_capital = True
                    if letter.isdigit():
                        has_digit = True
                
                if has_capital and has_digit:
                    user = User()
                    user.username = username
                    user.email = email
                    user.password = password
                    db.session.add(user)
                    db.session.commit()
                    return login()
                else:
                    return render_template('signup.html',error='Password must contain at least one capital letter and one number')    
            else:
                return render_template('signup.html',error='Password must be of length 8')
        return redirect('/notfound/User already exists.')
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return login()

@app.route('/main')
@login_required
def main():
    return render_template('merge.html',user=current_user)

@app.route('/10', methods=['GET', 'POST'])
@login_required
def know():
    if request.method == 'POST':
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        stream = request.form.get('stream')
        qualification = request.form.get('qualification')
        query = request.form.get('query')

        form_data = Form(
            name=name,
            mobile=mobile,
            stream=stream,
            qualification=qualification,
            query=query
        )

        db.session.add(form_data)
        db.session.commit()

        session['message'] = 'Form submitted successfully'

        return redirect(url_for('know'))

    message = session.pop('message', None)

    return render_template('10.html', user=current_user, message=message)


@app.route('/12', methods=['GET', 'POST'])
@login_required
def knowmo():
    if request.method == 'POST':
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        stream = request.form.get('stream')
        query = request.form.get('query')
        qualification="NA After 12th"


        form_data = Form(
            name=name,
            mobile=mobile,
            stream=stream,
            query=query,
            qualification=qualification
        )

        db.session.add(form_data)
        db.session.commit()

        session['message'] = 'Form submitted successfully'

        return redirect(url_for('knowmo'))

    message = session.pop('message', None)

    return render_template('12.html', user=current_user, message=message)



@app.route('/college', methods=['GET', 'POST'])
@login_required
def knowcollege():
    if request.method == 'POST':
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        stream = request.form.get('stream')
        qualification=request.form.get('qualification')
        query = request.form.get('query')


        form_data = Form(
            name=name,
            mobile=mobile,
            stream=stream,
            qualification=qualification,
            query=query
        )

        db.session.add(form_data)
        db.session.commit()

        session['message'] = 'Form submitted successfully'

        return redirect(url_for('knowcollege'))

    message = session.pop('message', None)

    return render_template('college.html', user=current_user, message=message)


@app.route('/personality', methods=['GET', 'POST'])
@login_required
def person():
    return render_template('personality.html',user=current_user)

@app.route('/process-form', methods=['POST'])
def process_form():
    # Get the selected options from the form data
    question1 = request.form['question1']
    question2 = request.form['question2']
    question3 = request.form['question3']
    question4 = request.form['question4']
    question5 = request.form['question5']
    question6 = request.form['question6']
    question7 = request.form['question7']
    question8 = request.form['question8']
    question9 = request.form['question9']
    question10 = request.form['question10']

    # Calculate the personality type based on the selected options
    personality_type = calculate_personality_type(question1, question2, question3, question4, question5, question6, question7, question8, question9, question10)
    
    # Return the result to the client
    return render_template('personality.html', personality_type=personality_type)

def calculate_personality_type(question1, question2, question3, question4, question5, question6, question7, question8, question9, question10):
    # Count the occurrences of each option
    option_counts = {
        'a': 0,
        'b': 0,
        'c': 0,
        'd': 0
    }

    # Update option counts based on the selected option
    option_counts[question1] += 1
    option_counts[question2] += 1
    option_counts[question3] += 1
    option_counts[question4] += 1
    option_counts[question5] += 1
    option_counts[question6] += 1
    option_counts[question7] += 1
    option_counts[question8] += 1
    option_counts[question9] += 1
    option_counts[question10] += 1

    # Determine the most selected option
    most_selected_option = max(option_counts, key=option_counts.get)

    # Map the most selected option to the corresponding personality type
    personality_types = {
        'a': 'You are Ambitious and Driven',
        'b': 'You are Relaxed and Flexible',
        'c': 'You are  Analytical and Detail-Oriented',
        'd': 'You are Calm and Resilient'
    }
    # Get the personality type based on the most selected option
    personality_type = personality_types[most_selected_option]

    return personality_type

@app.route('/forgot-password',methods=['GET', 'POST'])
def fog():
    return render_template('password.html',user=current_user)


def generate_password_reset_link(user_email):
    # Generate a unique token or code for the password reset request
    reset_token = str(uuid.uuid4())
    domain = request.host_url

    # Construct the password reset link using the generated token
    reset_link = reset_link = f'{domain}reset-password/{reset_token}'

    # Store the reset_token, user_email, and expiration time in a secure storage
    # (e.g., database) for later verification and password reset process

    return reset_link

@app.route('/reset-password-ok', methods=['POST'])
def reset_password():
    email = request.form.get('email')

    # Perform validation, database lookup, etc.
    # Generate a unique reset token or link
    reset_link = generate_password_reset_link(email)

    # Send the password reset email
    send_password_reset_email(email, reset_link)

    return 'Password reset email sent'

def send_password_reset_email(email, reset_link):
    # Configure SMTP server and credentials
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'auper1998@gmail.com'
    smtp_password = 'tecichujgjowbddg'

    # Create and send the email
    sender_email = 'noreply@example.com'
    subject = 'Password Reset Request'
    body = f'Click the following link to reset your password: {reset_link}'
    message = f'Subject: {subject}\n\n{body}'

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, email, message)

@app.route('/reset-password/<reset_token>', methods=['GET'])
def reset_password_page(reset_token):
    return render_template('reset.html', reset_token=reset_token)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_passwordss():
    if request.method == 'GET':
        reset_token = request.args.get('reset_token')
        return render_template('reset.html', reset_token=reset_token)
    elif request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('e-mail')

        if new_password != confirm_password:
            return "Passwords do not match"

        # Update the password in the database for the user associated with the email
        # Replace this with your actual database update code
        # For example, if you are using SQLAlchemy, you can do something like:
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = new_password
            db.session.commit()
            return "Password reset successful. You can now log in with your new password."
        else:
            return "User not found"


if __name__ == '__main__':
    app.run(host="0.0.0.0",port="5000")