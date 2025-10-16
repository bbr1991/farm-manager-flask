# In models.py
from app import db # Assuming db is initialized in app.py

class Flock(db.Model):
    # ... your existing Flock model ...
    id = db.Column(db.Integer, primary_key=True)
    flock_name = db.Column(db.String(100), nullable=False)
    # ... other flock fields ...

class JournalEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    debit_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    credit_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    related_contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'), nullable=True)
    is_closed = db.Column(db.Boolean, default=False)
    
    # ADD THIS LINE:
    related_flock_id = db.Column(db.Integer, db.ForeignKey('flock.id'), nullable=True) 
    
    # Optional: define relationship for easier access
    flock = db.relationship('Flock', backref='journal_entries')

    # ... other relationships or methods ...