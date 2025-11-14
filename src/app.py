# app.py
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
from datetime import datetime
import secrets
import json
import time
import os
from collections import defaultdict

def get_or_create_secret_key():
    """Load SECRET_KEY from file or create a new one that persists across restarts"""
    secret_file = 'secret_key.txt'

    # Try to load existing secret key
    if os.path.exists(secret_file):
        try:
            with open(secret_file, 'r') as f:
                secret_key = f.read().strip()
                if secret_key:
                    print(f"✓ Loaded existing SECRET_KEY from {secret_file}")
                    return secret_key
        except Exception as e:
            print(f"⚠ Warning: Could not read {secret_file}: {e}")

    # Generate new secret key and save it
    secret_key = secrets.token_hex(32)  # 64 characters
    try:
        with open(secret_file, 'w') as f:
            f.write(secret_key)
        print(f"✓ Generated new SECRET_KEY and saved to {secret_file}")
    except Exception as e:
        print(f"⚠ Warning: Could not save SECRET_KEY to {secret_file}: {e}")

    return secret_key

app = Flask(__name__)
app.config['SECRET_KEY'] = get_or_create_secret_key()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///party.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Initialize SocketIO with threading mode (optimal for Raspberry Pi)
socketio = SocketIO(
    app,
    async_mode='threading',
    cors_allowed_origins='*',  # Allow all origins in local network
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False
)

# Rate limiting for WebSocket events
rate_limit_storage = defaultdict(list)
MAX_EVENTS_PER_SECOND = 10

# Helper function for unified API responses
def api_response(status='success', data=None, error=None, code=200):
    """Einheitliche API-Response Format"""
    return jsonify({
        'status': status,
        'data': data,
        'error': error
    }), code

# Rate limiting helper for WebSocket
def check_rate_limit(sid):
    """Check if client exceeds rate limit (max 10 events per second)"""
    now = time.time()
    rate_limit_storage[sid] = [t for t in rate_limit_storage[sid] if now - t < 1]

    if len(rate_limit_storage[sid]) >= MAX_EVENTS_PER_SECOND:
        return False

    rate_limit_storage[sid].append(now)
    return True

# Helper to broadcast updates to all connected clients
def broadcast_update(event_name, data, room=None):
    """Broadcast an update to all clients or specific room"""
    if room:
        socketio.emit(event_name, data, room=room, skip_sid=None)
    else:
        socketio.emit(event_name, data)

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

    __table_args__ = (
        db.UniqueConstraint('truth_lie_id', 'user_id', name='uix_vote_user'),
    )

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
            return api_response('error', error='Not logged in', code=401)
        # Update last_seen timestamp
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()
        return f(*args, **kwargs)
    return decorated_function

# ===== WEBSOCKET EVENT HANDLERS =====
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f'Client connected: {request.sid}')
    emit('connected', {'sid': request.sid})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f'Client disconnected: {request.sid}')

    # Clean up rate limiting storage
    if request.sid in rate_limit_storage:
        del rate_limit_storage[request.sid]

    # Leave user room if logged in
    if 'user_id' in session:
        user_room = f"user_{session['user_id']}"
        leave_room(user_room)

        user = User.query.get(session['user_id'])
        if user:
            # Broadcast user left
            broadcast_update('user_status', {
                'user_id': user.id,
                'user_name': user.name,
                'status': 'offline'
            })

@socketio.on('request_update')
def handle_request_update(data):
    """Handle client request for specific updates"""
    if not check_rate_limit(request.sid):
        emit('error', {'message': 'Rate limit exceeded'})
        return

    update_type = data.get('type')

    if update_type == 'online_users':
        from datetime import timedelta
        threshold = datetime.now() - timedelta(minutes=5)
        online_users = User.query.filter(User.last_seen >= threshold).all()
        emit('online_users_update', {
            'users': [{'id': u.id, 'name': u.name} for u in online_users]
        })

    elif update_type == 'leaderboard':
        # Get global leaderboard (reuse logic from API)
        from sqlalchemy import func
        vote_points = db.session.query(
            Vote.user_id,
            (func.count(Vote.id) * 10).label('points')
        ).filter(Vote.is_correct == True).group_by(Vote.user_id).subquery()

        bingo_points = db.session.query(
            BingoCompletion.user_id,
            (func.count(BingoCompletion.id) * 5).label('points')
        ).group_by(BingoCompletion.user_id).subquery()

        compliment_points = db.session.query(
            Compliment.from_user_id.label('user_id'),
            (func.count(Compliment.id) * 2).label('points')
        ).group_by(Compliment.from_user_id).subquery()

        story_points = db.session.query(
            Story.user_id,
            func.count(Story.id).label('points')
        ).filter(Story.user_id != 0).group_by(Story.user_id).subquery()

        truthlie_creation_points = db.session.query(
            TruthLie.user_id,
            (func.count(TruthLie.id) * 5).label('points')
        ).group_by(TruthLie.user_id).subquery()

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
        ).order_by(db.desc('total_score')).all()

        leaderboard = [{'name': name, 'score': int(score)} for name, score in results if score > 0]
        emit('leaderboard_update', {'leaderboard': leaderboard})

@socketio.on('authenticate_user')
def handle_authenticate_user():
    """Handle user authentication after HTTP login"""
    if 'user_id' not in session:
        emit('error', {'message': 'Not authenticated'})
        return

    # Join user to their personal room
    user_room = f"user_{session['user_id']}"
    join_room(user_room)

    user = User.query.get(session['user_id'])
    if user:
        user.last_seen = datetime.utcnow()
        db.session.commit()

        print(f'User {user.name} (ID: {user.id}) authenticated and joined room {user_room}')

        # Broadcast user joined to all clients
        broadcast_update('user_status', {
            'user_id': user.id,
            'user_name': user.name,
            'status': 'online'
        })

        # Send online count to all clients
        from datetime import timedelta
        threshold = datetime.utcnow() - timedelta(minutes=5)
        online_count = User.query.filter(User.last_seen >= threshold).count()
        broadcast_update('online_count', {'count': online_count})

        # Confirm authentication to the client
        emit('authenticated', {'user_id': user.id, 'user_name': user.name, 'room': user_room})

@socketio.on('ping')
def handle_ping():
    """Handle ping for connection keepalive"""
    emit('pong')

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
        return api_response('error', error='Name required', code=400)

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

    return api_response('success', data={'name': user.name})

@app.route('/api/csrf-token', methods=['GET'])
@csrf.exempt  # Der Token-Endpoint selbst braucht keinen Token
def get_csrf_token():
    token = generate_csrf()
    return api_response('success', data={'csrf_token': token})

@app.route('/api/session', methods=['GET'])
@csrf.exempt
def get_session():
    """Check if user has a valid session"""
    if 'user_id' not in session:
        return api_response('error', error='No active session', code=401)

    user = User.query.get(session['user_id'])
    if not user:
        # Session exists but user was deleted
        session.clear()
        return api_response('error', error='User not found', code=404)

    # Update last_seen timestamp
    user.last_seen = datetime.utcnow()
    db.session.commit()

    return api_response('success', data={
        'user_id': user.id,
        'user_name': user.name
    })

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return api_response('success', data=[{'id': u.id, 'name': u.name} for u in users])

@app.route('/api/users/online', methods=['GET'])
def get_online_users():
    from datetime import timedelta
    # Consider users online if they were active in the last 5 minutes
    threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(User.last_seen >= threshold).all()
    return api_response('success', data=[{'id': u.id, 'name': u.name} for u in online_users])

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
        # Group votes by user and only keep the latest one (in case of duplicates)
        for vote in entry.votes:
            user_name = vote.user.name
            # Only add if not exists, or if this vote is newer
            if user_name not in votes or vote.created_at > votes[user_name].get('created_at', datetime.min):
                votes[user_name] = {
                    'guess': vote.guess.strip(),  # Trim whitespace
                    'correct': vote.guess.strip() == entry.lie.strip(),
                    'attempts': vote.attempts,
                    'is_correct': vote.is_correct,
                    'created_at': vote.created_at
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

    return api_response('success', data={
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
        return api_response('error', error='You already submitted your statements', code=400)

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

    # Broadcast new entry via WebSocket
    user = User.query.get(session['user_id'])
    broadcast_update('truthlie_new_entry', {
        'user_name': user.name,
        'entry_id': entry.id
    })

    return api_response('success')

@app.route('/api/truthlie/vote', methods=['POST'])
@require_login
def vote_truthlie():
    data = request.json

    # Get the entry to check the correct answer
    entry = TruthLie.query.get(data['entry_id'])
    if not entry:
        return api_response('error', error='Entry not found', code=404)

    # Normalize the guess (trim whitespace)
    guess = data['guess'].strip()
    lie = entry.lie.strip()

    # Check if already voted correctly
    existing = Vote.query.filter_by(
        truth_lie_id=data['entry_id'],
        user_id=session['user_id']
    ).first()

    if existing and existing.is_correct:
        return api_response('error', error='Already guessed correctly', code=400)

    # Check if this guess is correct
    is_correct = guess == lie

    if existing:
        # Update existing vote with new guess and increment attempts
        existing.guess = guess
        existing.attempts += 1
        existing.is_correct = is_correct
    else:
        # Create new vote
        existing = Vote(
            truth_lie_id=data['entry_id'],
            user_id=session['user_id'],
            guess=guess,
            attempts=1,
            is_correct=is_correct
        )
        db.session.add(existing)

    db.session.commit()

    # Broadcast vote update via WebSocket
    user = User.query.get(session['user_id'])
    broadcast_update('truthlie_update', {
        'entry_id': entry.id,
        'user_name': user.name,
        'is_correct': is_correct
    })

    # If correct, broadcast leaderboard update
    if is_correct:
        broadcast_update('trigger_confetti', {})

    return api_response('success', data={'correct': is_correct, 'attempts': existing.attempts})

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
    return api_response('success', data=scores)

# Compliments endpoints
@app.route('/api/compliments/target', methods=['GET'])
@require_login
def get_compliment_target():
    users = User.query.filter(User.id != session['user_id']).all()
    if not users:
        return api_response('success', data={'target': None})

    import random
    target = random.choice(users)
    return api_response('success', data={'target': target.name, 'target_id': target.id})

@app.route('/api/compliments/received', methods=['GET'])
@require_login
def get_received_compliments():
    compliments = Compliment.query.filter_by(to_user_id=session['user_id']).all()
    return api_response('success', data=[{'text': c.text} for c in compliments])

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

    # Send WebSocket events
    from_user = User.query.get(session['user_id'])
    to_user = User.query.get(data['to_user_id'])

    # Send confirmation to sender
    broadcast_update('new_compliment_sent', {
        'to_user': to_user.name
    }, room=f"user_{session['user_id']}")

    # Send notification to receiver (private message)
    broadcast_update('new_compliment_received', {
        'text': data['text'],
        'from_user': from_user.name
    }, room=f"user_{data['to_user_id']}")

    # Trigger confetti for receiver
    broadcast_update('trigger_confetti', {}, room=f"user_{data['to_user_id']}")

    return api_response('success')

@app.route('/api/compliments/stats', methods=['GET'])
@require_login
def get_compliment_stats():
    sent_count = Compliment.query.filter_by(from_user_id=session['user_id']).count()
    received_count = Compliment.query.filter_by(to_user_id=session['user_id']).count()

    return api_response('success', data={
        'sent': sent_count,
        'received': received_count
    })

# Bingo endpoints
@app.route('/api/bingo', methods=['GET'])
@require_login
def get_bingo():
    completions = BingoCompletion.query.filter_by(user_id=session['user_id']).all()
    completed_indices = [c.item_index for c in completions]

    return api_response('success', data={'completed': completed_indices})

@app.route('/api/bingo/leaderboard', methods=['GET'])
def get_bingo_leaderboard():
    users = User.query.all()
    scores = []

    for user in users:
        count = BingoCompletion.query.filter_by(user_id=user.id).count()
        scores.append({'name': user.name, 'score': count})

    scores.sort(key=lambda x: x['score'], reverse=True)
    return api_response('success', data=scores)

@app.route('/api/bingo/toggle', methods=['POST'])
@require_login
def toggle_bingo():
    data = request.json
    item_index = data['item_index']

    existing = BingoCompletion.query.filter_by(
        user_id=session['user_id'],
        item_index=item_index
    ).first()

    is_completion = False
    if existing:
        db.session.delete(existing)
    else:
        completion = BingoCompletion(user_id=session['user_id'], item_index=item_index)
        db.session.add(completion)
        is_completion = True

    db.session.commit()

    # Get updated progress
    completions = BingoCompletion.query.filter_by(user_id=session['user_id']).all()
    completed_indices = [c.item_index for c in completions]

    # Broadcast bingo update
    user = User.query.get(session['user_id'])
    broadcast_update('bingo_update', {
        'user_name': user.name,
        'completed_count': len(completed_indices)
    })

    # Check for full bingo
    if len(completed_indices) == 12 and is_completion:
        broadcast_update('bingo_complete', {
            'user_name': user.name
        })
        broadcast_update('trigger_confetti', {})

    return api_response('success', data={'completed': completed_indices})

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

    return api_response('success', data=leaderboard)

# Story endpoints
@app.route('/api/story', methods=['GET'])
@require_login
def get_story():
    sentences = Story.query.order_by(Story.created_at).all()
    return api_response('success', data=[s.sentence for s in sentences])

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

    # Broadcast story update via WebSocket
    user = User.query.get(session['user_id'])
    sentences = Story.query.order_by(Story.created_at).all()

    broadcast_update('story_update', {
        'user_name': user.name,
        'sentence': data['sentence'],
        'full_story': [s.sentence for s in sentences]
    })

    return api_response('success')

@app.route('/api/story/stats', methods=['GET'])
@require_login
def get_story_stats():
    user_sentences = Story.query.filter_by(user_id=session['user_id']).count()
    total_sentences = Story.query.filter(Story.user_id != 0).count()  # Exclude initial sentence

    return api_response('success', data={
        'contributed': user_sentences,
        'total': total_sentences
    })

if __name__ == '__main__':
    # Use socketio.run instead of app.run for WebSocket support
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        #allow_unsafe_werkzeug=True  # For development only
    )