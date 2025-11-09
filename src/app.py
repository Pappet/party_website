# app.py
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///party.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TruthLie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    statements = db.Column(db.Text, nullable=False)  # JSON string
    lie = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='truth_lies')

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    truth_lie_id = db.Column(db.Integer, db.ForeignKey('truth_lie.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    guess = db.Column(db.String(200), nullable=False)
    truth_lie = db.relationship('TruthLie', backref='votes')
    user = db.relationship('User')

class Compliment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])

class BingoCompletion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_index = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref='bingo_completions')

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sentence = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')

# Initialize database
with app.app_context():
    db.create_all()
    # Add initial story sentence if empty
    if Story.query.count() == 0:
        initial = Story(user_id=0, sentence="Es war einmal auf einer fantastischen Party...")
        db.session.add(initial)
        db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    name = data.get('name', '').strip()
    
    if not name:
        return jsonify({'error': 'Name required'}), 400
    
    user = User.query.filter_by(name=name).first()
    if not user:
        user = User(name=name)
        db.session.add(user)
        db.session.commit()
    
    session['user_id'] = user.id
    session['user_name'] = user.name
    
    return jsonify({'success': True, 'name': user.name})

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'name': u.name} for u in users])

# Truth or Lie endpoints
@app.route('/api/truthlie', methods=['GET'])
def get_truthlies():
    entries = TruthLie.query.all()
    result = []
    
    for entry in entries:
        votes = {}
        for vote in entry.votes:
            votes[vote.user.name] = {
                'guess': vote.guess,
                'correct': vote.guess == entry.lie
            }
        
        result.append({
            'id': entry.id,
            'user': entry.user.name,
            'statements': json.loads(entry.statements),
            'lie': entry.lie,
            'votes': votes
        })
    
    return jsonify(result)

@app.route('/api/truthlie', methods=['POST'])
def submit_truthlie():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    statements = [data['truth1'], data['truth2'], data['lie']]
    import random
    random.shuffle(statements)
    
    entry = TruthLie(
        user_id=session['user_id'],
        statements=json.dumps(statements),
        lie=data['lie']
    )
    db.session.add(entry)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/truthlie/vote', methods=['POST'])
def vote_truthlie():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    
    # Check if already voted
    existing = Vote.query.filter_by(
        truth_lie_id=data['entry_id'],
        user_id=session['user_id']
    ).first()
    
    if existing:
        return jsonify({'error': 'Already voted'}), 400
    
    vote = Vote(
        truth_lie_id=data['entry_id'],
        user_id=session['user_id'],
        guess=data['guess']
    )
    db.session.add(vote)
    db.session.commit()
    
    return jsonify({'success': True})

# Compliments endpoints
@app.route('/api/compliments/target', methods=['GET'])
def get_compliment_target():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    users = User.query.filter(User.id != session['user_id']).all()
    if not users:
        return jsonify({'target': None})
    
    import random
    target = random.choice(users)
    return jsonify({'target': target.name, 'target_id': target.id})

@app.route('/api/compliments/received', methods=['GET'])
def get_received_compliments():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    compliments = Compliment.query.filter_by(to_user_id=session['user_id']).all()
    return jsonify([{'text': c.text} for c in compliments])

@app.route('/api/compliments', methods=['POST'])
def submit_compliment():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    compliment = Compliment(
        from_user_id=session['user_id'],
        to_user_id=data['to_user_id'],
        text=data['text']
    )
    db.session.add(compliment)
    db.session.commit()
    
    return jsonify({'success': True})

# Bingo endpoints
@app.route('/api/bingo', methods=['GET'])
def get_bingo():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    completions = BingoCompletion.query.filter_by(user_id=session['user_id']).all()
    completed_indices = [c.item_index for c in completions]
    
    return jsonify({'completed': completed_indices})

@app.route('/api/bingo/leaderboard', methods=['GET'])
def get_bingo_leaderboard():
    users = User.query.all()
    scores = []
    
    for user in users:
        count = BingoCompletion.query.filter_by(user_id=user.id).count()
        scores.append({'name': user.name, 'score': count})
    
    scores.sort(key=lambda x: x['score'], reverse=True)
    return jsonify(scores)

@app.route('/api/bingo/toggle', methods=['POST'])
def toggle_bingo():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    item_index = data['item_index']
    
    existing = BingoCompletion.query.filter_by(
        user_id=session['user_id'],
        item_index=item_index
    ).first()
    
    if existing:
        db.session.delete(existing)
    else:
        completion = BingoCompletion(user_id=session['user_id'], item_index=item_index)
        db.session.add(completion)
    
    db.session.commit()
    return jsonify({'success': True})

# Story endpoints
@app.route('/api/story', methods=['GET'])
def get_story():
    sentences = Story.query.order_by(Story.created_at).all()
    return jsonify([s.sentence for s in sentences])

@app.route('/api/story', methods=['POST'])
def add_to_story():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    story = Story(
        user_id=session['user_id'],
        sentence=data['sentence']
    )
    db.session.add(story)
    db.session.commit()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)