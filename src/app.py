# app.py
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from functools import wraps
from datetime import datetime
import secrets
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///party.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

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
    attempts = db.Column(db.Integer, default=1)
    is_correct = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
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

# Decorator for protected routes
def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not logged in'}), 401
        # Update last_seen timestamp
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
@csrf.exempt
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
    else:
        # Update last_seen for existing users
        user.last_seen = datetime.utcnow()
        db.session.commit()

    session['user_id'] = user.id
    session['user_name'] = user.name

    return jsonify({'success': True, 'name': user.name})

@app.route('/api/csrf-token', methods=['GET'])
@csrf.exempt  # Der Token-Endpoint selbst braucht keinen Token
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'status': 'success', 'data': {'csrf_token': token}})

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': u.id, 'name': u.name} for u in users])

@app.route('/api/users/online', methods=['GET'])
def get_online_users():
    from datetime import timedelta
    # Consider users online if they were active in the last 5 minutes
    threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= threshold).all()
    return jsonify([{'id': u.id, 'name': u.name} for u in online_users])

# Truth or Lie endpoints
@app.route('/api/truthlie', methods=['GET'])
@require_login
def get_truthlies():

    entries = TruthLie.query.all()
    result = []
    user_has_entry = False
    user_entry = None

    for entry in entries:
        votes = {}
        for vote in entry.votes:
            votes[vote.user.name] = {
                'guess': vote.guess,
                'correct': vote.guess == entry.lie,
                'attempts': vote.attempts,
                'is_correct': vote.is_correct
            }

        entry_data = {
            'id': entry.id,
            'user': entry.user.name,
            'statements': json.loads(entry.statements),
            'lie': entry.lie,
            'votes': votes
        }

        # Check if this is the current user's entry
        if entry.user_id == session['user_id']:
            user_has_entry = True
            user_entry = entry_data
        else:
            result.append(entry_data)

    return jsonify({
        'entries': result,
        'user_has_entry': user_has_entry,
        'user_entry': user_entry
    })

@app.route('/api/truthlie', methods=['POST'])
@require_login
def submit_truthlie():
    # Check if user already has an entry
    existing_entry = TruthLie.query.filter_by(user_id=session['user_id']).first()
    if existing_entry:
        return jsonify({'error': 'You already submitted your statements'}), 400

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
@require_login
def vote_truthlie():
    data = request.json

    # Get the entry to check the correct answer
    entry = TruthLie.query.get(data['entry_id'])
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404

    # Check if already voted correctly
    existing = Vote.query.filter_by(
        truth_lie_id=data['entry_id'],
        user_id=session['user_id']
    ).first()

    if existing and existing.is_correct:
        return jsonify({'error': 'Already guessed correctly'}), 400

    # Check if this guess is correct
    is_correct = data['guess'] == entry.lie

    if existing:
        # Update existing vote with new guess and increment attempts
        existing.guess = data['guess']
        existing.attempts += 1
        existing.is_correct = is_correct
    else:
        # Create new vote
        existing = Vote(
            truth_lie_id=data['entry_id'],
            user_id=session['user_id'],
            guess=data['guess'],
            attempts=1,
            is_correct=is_correct
        )
        db.session.add(existing)

    db.session.commit()

    return jsonify({'success': True, 'correct': is_correct, 'attempts': existing.attempts})

@app.route('/api/truthlie/leaderboard', methods=['GET'])
def get_truthlie_leaderboard():
    users = User.query.all()
    scores = []

    for user in users:
        # Get all correct votes by this user
        correct_votes = Vote.query.filter_by(user_id=user.id, is_correct=True).all()

        if correct_votes:
            total_attempts = sum(vote.attempts for vote in correct_votes)
            scores.append({
                'name': user.name,
                'total_attempts': total_attempts,
                'solved_count': len(correct_votes)
            })

    # Sort by total attempts (ascending - fewer is better)
    scores.sort(key=lambda x: x['total_attempts'])
    return jsonify(scores)

# Compliments endpoints
@app.route('/api/compliments/target', methods=['GET'])
@require_login
def get_compliment_target():
    users = User.query.filter(User.id != session['user_id']).all()
    if not users:
        return jsonify({'target': None})
    
    import random
    target = random.choice(users)
    return jsonify({'target': target.name, 'target_id': target.id})

@app.route('/api/compliments/received', methods=['GET'])
@require_login
def get_received_compliments():
    compliments = Compliment.query.filter_by(to_user_id=session['user_id']).all()
    return jsonify([{'text': c.text} for c in compliments])

@app.route('/api/compliments', methods=['POST'])
@require_login
def submit_compliment():
    data = request.json
    compliment = Compliment(
        from_user_id=session['user_id'],
        to_user_id=data['to_user_id'],
        text=data['text']
    )
    db.session.add(compliment)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/api/compliments/stats', methods=['GET'])
@require_login
def get_compliment_stats():
    sent_count = Compliment.query.filter_by(from_user_id=session['user_id']).count()
    received_count = Compliment.query.filter_by(to_user_id=session['user_id']).count()

    return jsonify({
        'sent': sent_count,
        'received': received_count
    })

# Bingo endpoints
@app.route('/api/bingo', methods=['GET'])
@require_login
def get_bingo():
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
@require_login
def toggle_bingo():
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

# Global Leaderboard endpoint
@app.route('/api/leaderboard/global', methods=['GET'])
def get_global_leaderboard():
    from sqlalchemy import func, case
    from sqlalchemy.orm import aliased

    # Subquery for Vote points (+10 per correct vote)
    vote_points = db.session.query(
        Vote.user_id,
        (func.count(Vote.id) * 10).label('points')
    ).filter(
        Vote.is_correct == True
    ).group_by(Vote.user_id).subquery()

    # Subquery for BingoCompletion points (+5 per completion)
    bingo_points = db.session.query(
        BingoCompletion.user_id,
        (func.count(BingoCompletion.id) * 5).label('points')
    ).group_by(BingoCompletion.user_id).subquery()

    # Subquery for Compliment points (+2 per sent compliment)
    compliment_points = db.session.query(
        Compliment.from_user_id.label('user_id'),
        (func.count(Compliment.id) * 2).label('points')
    ).group_by(Compliment.from_user_id).subquery()

    # Subquery for Story points (+1 per story sentence, excluding user_id=0)
    story_points = db.session.query(
        Story.user_id,
        func.count(Story.id).label('points')
    ).filter(
        Story.user_id != 0
    ).group_by(Story.user_id).subquery()

    # Subquery for TruthLie creation points (+5 per created entry)
    truthlie_creation_points = db.session.query(
        TruthLie.user_id,
        (func.count(TruthLie.id) * 5).label('points')
    ).group_by(TruthLie.user_id).subquery()

    # Join all subqueries with User table and calculate total score
    results = db.session.query(
        User.name,
        (
            func.coalesce(vote_points.c.points, 0) +
            func.coalesce(bingo_points.c.points, 0) +
            func.coalesce(compliment_points.c.points, 0) +
            func.coalesce(story_points.c.points, 0) +
            func.coalesce(truthlie_creation_points.c.points, 0)
        ).label('total_score')
    ).outerjoin(
        vote_points, User.id == vote_points.c.user_id
    ).outerjoin(
        bingo_points, User.id == bingo_points.c.user_id
    ).outerjoin(
        compliment_points, User.id == compliment_points.c.user_id
    ).outerjoin(
        story_points, User.id == story_points.c.user_id
    ).outerjoin(
        truthlie_creation_points, User.id == truthlie_creation_points.c.user_id
    ).order_by(
        db.desc('total_score')
    ).all()

    # Format results as list of dicts
    leaderboard = [{'name': name, 'score': int(score)} for name, score in results if score > 0]

    return jsonify(leaderboard)

# Story endpoints
@app.route('/api/story', methods=['GET'])
@require_login
def get_story():
    sentences = Story.query.order_by(Story.created_at).all()
    return jsonify([s.sentence for s in sentences])

@app.route('/api/story', methods=['POST'])
@require_login
def add_to_story():
    data = request.json
    story = Story(
        user_id=session['user_id'],
        sentence=data['sentence']
    )
    db.session.add(story)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/api/story/stats', methods=['GET'])
@require_login
def get_story_stats():
    user_sentences = Story.query.filter_by(user_id=session['user_id']).count()
    total_sentences = Story.query.filter(Story.user_id != 0).count()  # Exclude initial sentence

    return jsonify({
        'contributed': user_sentences,
        'total': total_sentences
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)