from flask import Flask, render_template, redirect, request, url_for, flash, session, jsonify
from pymongo import MongoClient
import os
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
from flask_cors import CORS
from flask_babel import Babel, gettext as _
import matplotlib
matplotlib.use('Agg')  # Set the backend to 'Agg' (non-interactive)
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime, timedelta
import requests
import json
from groq import Groq

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# Multi-language support
app.config['LANGUAGES'] = {'en': 'English', 'hi': 'Hindi', 'mr': 'Marathi'}
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
babel = Babel(app)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# Allow OAuth2 to work in a non-HTTPS environment for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Google OAuth2 credentials
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
# Database connection system
client = MongoClient('mongodb://localhost:27017/')
db = client['DesiBazzar']
user_collection = db['users']
investment_collection = db['investments']
wallet_collection = db['wallet']  # Collection for wallet balance
transactions_collection = db['transactions']  # Collection for profit/loss transactions
stocks_collection = db['stocks']  # Collection for stock data
bonds_collection = db['bonds']  # Collection for bond data
investments_collection = db['investments']
insurance_collection = db['insurance']

def get_historical_data(stock_name, period):
    stock = stocks_collection.find_one({"Name": stock_name})
    if not stock:
        print(f"No stock found with name: {stock_name}")
        return None

    # Fetch dates and prices based on the period
    if period == "1d":
        dates = stock.get("1d_dates", "").split(",")
        prices = stock.get("1d_prices", "").split(",")
    elif period == "1w":
        dates = stock.get("1w_dates", "").split(",")
        prices = stock.get("1w_prices", "").split(",")
    elif period == "1m":
        dates = stock.get("1m_dates", "").split(",")
        prices = stock.get("1m_prices", "").split(",")
    elif period == "1y":
        dates = stock.get("1y_dates", "").split(",")
        prices = stock.get("1y_prices", "").split(",")
    elif period == "5y":
        dates = stock.get("5y_dates", "").split(",")
        prices = stock.get("5y_prices", "").split(",")
    else:
        # Default to 1d if period is invalid
        dates = stock.get("1d_dates", "").split(",")
        prices = stock.get("1d_prices", "").split(",")

    # Combine dates and prices into a list of dictionaries
    historical_data = []
    for date, price in zip(dates, prices):
        historical_data.append({
            "date": date.strip(),
            "price": float(price.strip())
        })

    return historical_data

def analyze_bonds():
    suggestions = []
    bonds = list(bonds_collection.find({}))
    for bond in bonds:
        isin = bond.get("ISIN")
        descriptor = bond.get("DESCRIPTOR")
        last_trade_price = float(bond.get("LAST_TRADE_PRICE", 0))
        weighted_avg_price = float(bond.get("WEIGHTED_AVERAGE_PRICE", 0))

        # Simple suggestion logic
        if last_trade_price < weighted_avg_price * 0.95:  # If current price is 5% below average
            suggestions.append({
                "name": descriptor,
                "action": "Buy",
                "reason": f"Current price ({last_trade_price}) is below the weighted average ({weighted_avg_price:.2f})."
            })
        elif last_trade_price > weighted_avg_price * 1.05:  # If current price is 5% above average
            suggestions.append({
                "name": descriptor,
                "action": "Sell",
                "reason": f"Current price ({last_trade_price}) is above the weighted average ({weighted_avg_price:.2f})."
            })

    return suggestions

# Function to analyze insurance and generate suggestions
def analyze_insurance():
    suggestions = []
    insurance_policies = list(insurance_collection.find({}))
    for policy in insurance_policies:
        symbol = policy.get("Symbol")
        premium_rate = float(policy.get("Premium_Rate", 0))
        coverage = float(policy.get("Coverage", 0))

        # Simple suggestion logic
        if premium_rate < coverage * 0.01:  # If premium is less than 1% of coverage
            suggestions.append({
                "name": symbol,
                "action": "Buy",
                "reason": f"Premium rate ({premium_rate}) is very low compared to coverage ({coverage})."
            })

    return suggestions

# Function to analyze stocks and generate suggestions
def get_current_price(stock_name):
    """
    Fetch the current price of a stock from the database.
    """
    stock = stocks_collection.find_one({"Name": stock_name})
    if stock:
        return float(stock.get("Price", 0))  # Return the current price
    else:
        print(f"No stock found with name: {stock_name}")
        return 0  # Return 0 if the stock is not found
    
def analyze_stocks():
    suggestions = []
    stocks = list(stocks_collection.find({}))
    for stock in stocks:
        name = stock.get("Name")
        latest_price = float(stock.get("Price", 0))  # Latest price from MongoDB
        current_price = get_current_price(name)  # Fetch current price from an API or user input

        if current_price:
            # Calculate profit/loss
            profit_loss = current_price - latest_price

            # Simple suggestion logic
            if current_price < latest_price * 0.95:  # If current price is 5% below latest price
                suggestions.append({
                    "name": name,
                    "action": "Buy",
                    "reason": f"Current price ({current_price}) is below the latest price ({latest_price:.2f}).",
                    "profit_loss": profit_loss  # Add profit/loss for sorting
                })
            elif current_price > latest_price * 1.05:  # If current price is 5% above latest price
                suggestions.append({
                    "name": name,
                    "action": "Sell",
                    "reason": f"Current price ({current_price}) is above the latest price ({latest_price:.2f}).",
                    "profit_loss": profit_loss  # Add profit/loss for sorting
                })

    # Sort suggestions by profit/loss (most negative to most positive)
    suggestions.sort(key=lambda x: x["profit_loss"])

    # Return only top 10 suggestions
    return suggestions[:10]


# Route to display suggestions
@app.route('/suggestions')
def suggestions():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = user_collection.find_one({'username': session['username']})
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('login'))

    # Generate suggestions (only stocks)
    stock_suggestions = analyze_stocks()

    return render_template(
        'suggestions/index.html',
        stock_suggestions=stock_suggestions
    )

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/set_language/<language>')
def set_language(language):
    if language in app.config['LANGUAGES']:
        session['language'] = language
    return redirect(request.referrer or url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            password = request.form.get('password')

            # Debug: Print form data
            print(f"Login Attempt - Username: {username}, Password: {password}")

            # Check if all fields are present
            if not username or not password:
                flash('Username and password are required.', 'error')
                return redirect(url_for('login'))

            # Find the user in the database
            user = user_collection.find_one({'username': username})

            # Debug: Print the user document from MongoDB
            print(f"User Document: {user}")

            # Check if the user exists and the password is correct
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                flash('You were successfully logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                return redirect(url_for('login'))

        except Exception as e:
            # Debug: Print the error
            print(f"Error during login: {e}")
            flash('An error occurred during login. Please try again.', 'error')
            return redirect(url_for('login'))

    return render_template('login/index.html')

@app.route('/login/google')
def login_google():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    scopes = ["openid", "email", "profile"]

    google = OAuth2Session(GOOGLE_CLIENT_ID, scope=scopes, redirect_uri=url_for('callback', _external=True))

    authorization_url, state = google.authorization_url(authorization_endpoint, access_type="offline", prompt="select_account")

    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route("/login/callback")
def callback():
    google = OAuth2Session(GOOGLE_CLIENT_ID, state=session['oauth_state'], redirect_uri=url_for('callback', _external=True))
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token = google.fetch_token(
        token_url=token_endpoint,
        authorization_response=request.url,
        client_secret=GOOGLE_CLIENT_SECRET
    )

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    userinfo_response = google.get(userinfo_endpoint)

    userinfo = userinfo_response.json()

    if userinfo.get("email_verified"):
        unique_id = userinfo["sub"]
        users_email = userinfo["email"]
        picture = userinfo["picture"]
        users_name = userinfo["given_name"]

        user = user_collection.find_one({"username": users_name})
        if not user:
            user_collection.insert_one({
                "username": users_name,
                "email": users_email,
                "profile_pic": picture,
                "password": None,
                "tokens": 1000000  # Set initial tokens to 10 lakh
            })

        session['username'] = users_name
        flash(_('You were successfully logged in with Google'), 'success')
    else:
        flash(_('User email not available or not verified by Google.'), 'error')
    return redirect(url_for('dashboard'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            # Debug: Print form data
            print(f"Signup Attempt - Username: {username}, Email: {email}, Password: {password}, Confirm Password: {confirm_password}")

            # Check if all fields are present
            if not username or not email or not password or not confirm_password:
                flash('All fields are required.', 'error')
                return redirect(url_for('signup'))

            # Check if passwords match
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return redirect(url_for('signup'))

            # Check if the username or email already exists
            if user_collection.find_one({'username': username}):
                flash('Username already exists. Please choose a different one.', 'error')
                return redirect(url_for('signup'))

            if user_collection.find_one({'email': email}):
                flash('Email already exists. Please use a different email.', 'error')
                return redirect(url_for('signup'))

            # Hash the password
            hashed_password = generate_password_hash(password)

            # Insert the new user into the database
            user_data = {
                'username': username,
                'email': email,
                'password': hashed_password,
                'tokens': 1000000  # Set initial tokens to 10 lakh
            }
            result = user_collection.insert_one(user_data)

            # Debug: Print the result of the insert operation
            print(f"User inserted with ID: {result.inserted_id}")

            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            # Debug: Print the error
            print(f"Error during signup: {e}")
            flash('An error occurred during signup. Please try again.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup/index.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash(_('You were successfully logged out.'), 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = user_collection.find_one({'username': session['username']})
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('login'))

    # Ensure the user has at least 10 lakh tokens
    if 'tokens' not in user:
        user_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'tokens': 1000000}}
        )
        user['tokens'] = 1000000

    user_tokens = user.get('tokens', 1000000)  # Default to 10 lakh if 'tokens' is missing

    # Fetch wallet balance
    wallet = wallet_collection.find_one({'user_id': user['_id']})
    wallet_balance = wallet.get('balance', 0) if wallet else 0

    # Fetch profit/loss transactions
    transactions = list(transactions_collection.find({'user_id': user['_id']}))

    # Calculate total profit/loss from transactions
    total_profit_loss_from_transactions = sum(txn.get('profit_loss', 0) for txn in transactions)

    # Fetch investments and calculate totals
    investments = list(investments_collection.find({'user_id': user['_id']}))

    # Initialize variables for totals
    total_invested = 0
    total_current_value = 0
    total_profit_loss_from_investments = 0
    total_one_day_return = 0

    # Calculate totals for each investment
    for investment in investments:
        try:
            # Skip if 'asset_type' is missing
            if 'asset_type' not in investment:
                print(f"Investment missing 'asset_type': {investment}")
                continue

            if investment['asset_type'] == 'Stock':
                # Skip if 'asset_name' is missing
                if 'asset_name' not in investment:
                    print(f"Investment missing 'asset_name': {investment}")
                    continue

                # Fetch current price of the stock
                stock = stocks_collection.find_one({"Name": investment['asset_name']})
                if stock:
                    current_price = float(stock['Price'])  # Fetch the current price
                else:
                    current_price = 0  # Default to 0 if the stock is not found

                purchase_price = float(investment['price'])
                quantity = int(investment['quantity'])

                # Calculate current value and profit/loss
                investment['current_value'] = current_price * quantity
                investment['purchase_value'] = purchase_price * quantity
                investment['profit_loss'] = investment['current_value'] - investment['purchase_value']

                # Calculate 1D return (assuming 1D price change is available in the stock data)
                if '1d_prices' in stock:
                    prices_1d = stock['1d_prices'].split(",")
                    if len(prices_1d) >= 2:
                        previous_price = float(prices_1d[-2].strip())  # Second last price
                        current_price_1d = float(prices_1d[-1].strip())  # Latest price
                        investment['one_day_return'] = (current_price_1d - previous_price) * quantity
                    else:
                        investment['one_day_return'] = 0
                else:
                    investment['one_day_return'] = 0

                # Update totals
                total_invested += investment['purchase_value']
                total_current_value += investment['current_value']
                total_profit_loss_from_investments += investment['profit_loss']
                total_one_day_return += investment.get('one_day_return', 0)
        except KeyError as e:
            print(f"KeyError in investment: {investment}, Error: {e}")
            continue  # Skip this investment if any key is missing

    # Combine profit/loss from transactions and investments
    total_profit_loss = total_profit_loss_from_transactions + total_profit_loss_from_investments

    return render_template(
        'dashboard/index.html',
        investments=investments,
        total_invested=total_invested,
        total_current_value=total_current_value,
        total_profit_loss=total_profit_loss,
        total_one_day_return=total_one_day_return,
        tokens=user_tokens,  # Pass the user's token balance to the template
        wallet_balance=wallet_balance,  # Pass the wallet balance to the template
        transactions=transactions  # Pass the transactions to the template
    )
@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = user_collection.find_one({'username': session['username']})
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('login'))

    amount = float(request.form['amount'])  # Convert to float

    # Fetch wallet balance
    wallet = wallet_collection.find_one({'user_id': user['_id']})
    if not wallet or wallet.get('balance', 0) < amount:
        flash('Insufficient balance in wallet!', 'error')
        return redirect(url_for('dashboard'))

    # Deduct amount from wallet
    wallet_collection.update_one(
        {'user_id': user['_id']},
        {'$inc': {'balance': -amount}}
    )

    # Add amount to user's tokens
    user_collection.update_one(
        {'_id': user['_id']},
        {'$inc': {'tokens': amount}}
    )

    flash(f'Successfully withdrew ₹{amount:.2f} from your wallet.', 'success')
    return redirect(url_for('dashboard'))
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        stock_name = request.form.get('stock_name').strip()  # Remove extra spaces
        quantity = int(request.form.get('quantity', 0))  # Convert to integer
        price = float(request.form.get('price', 0))  # Convert to float

        # Fetch stock details from the database (case-insensitive search)
        stock = stocks_collection.find_one({"Name": {"$regex": f"^{stock_name}$", "$options": "i"}})
        if not stock:
            flash(f'Stock not found for name: {stock_name}', 'error')
            return redirect(url_for('buy'))

        # Check if the requested quantity is available
        if stock.get("total_quantity", 0) < quantity:
            flash(f'Only {stock["total_quantity"]} stocks available for {stock_name}. You cannot purchase {quantity} stocks.', 'error')
            return redirect(url_for('buy'))

        # Calculate total price and brokerage
        total_price = quantity * price  # Ensure quantity and price are numbers
        brokerage = total_price * 0.005  # 0.5% brokerage
        final_amount = total_price + brokerage

        # Remove decimal part from final_amount
        final_amount = int(final_amount)  # Convert to integer to remove decimal part

        user = user_collection.find_one({'username': session['username']})
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('login'))

        # Check if the user has enough tokens
        if user['tokens'] < final_amount:
            flash(f'Insufficient tokens! You need {final_amount} tokens but only have {user["tokens"]}.', 'error')
            return redirect(url_for('buy'))

        # Deduct tokens from the user's account
        user_collection.update_one(
            {'_id': user['_id']},
            {'$inc': {'tokens': -final_amount}}
        )

        # Create investment record
        investment = {
            'user_id': ObjectId(user['_id']),  # Convert user ID to ObjectId
            'stock_name': stock['Name'],  # Use stock name from database
            'asset_name': stock['Name'],  # Add asset name
            'asset_type': stock.get('industry', 'Stock'),  # Add asset type (industry)
            'quantity': quantity,
            'price': price,
            'brokerage': brokerage,
            'total_price': total_price,
            'final_amount': final_amount,
            'date': datetime.now()
        }
        investments_collection.insert_one(investment)

        # Update the total quantity of the stock
        new_quantity = stock["total_quantity"] - quantity
        stocks_collection.update_one(
            {"_id": stock["_id"]},
            {"$set": {"total_quantity": new_quantity}}
        )

        flash(f'Stock purchased successfully! Total Amount: ₹{final_amount}', 'success')
        return redirect(url_for('dashboard'))

    # Fetch all stocks with name, price, and total quantity
    stocks = list(stocks_collection.find({}, {"Name": 1, "Price": 1, "industry": 1, "total_quantity": 1}))
    return render_template('buy/index.html', stocks=stocks)

@app.route('/graph-data')
def graph_data():
    stock_name = request.args.get('stock_name', 'Adani Enterprises')  # Default stock name
    period = request.args.get('period', '1d')  # Default period

    # Fetch data for the selected period
    historical_data = get_historical_data(stock_name, period)
    if historical_data:
        dates = [entry["date"] for entry in historical_data]
        prices = [entry["price"] for entry in historical_data]
        return jsonify({
            "dates": dates,
            "prices": prices
        })
    else:
        return jsonify({"error": "No data available for this period."}), 404

@app.route('/sell/<investment_id>', methods=['GET', 'POST'])
def sell(investment_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch the investment details
    investment = investments_collection.find_one({'_id': ObjectId(investment_id)})
    if not investment:
        flash('Investment not found.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Handle the sale of the stock
        quantity_to_sell = int(request.form['quantity'])  # Convert to integer

        if quantity_to_sell > investment['quantity']:
            flash('You cannot sell more stocks than you own.', 'error')
            return redirect(url_for('sell', investment_id=investment_id))

        # Fetch the stock details
        stock = stocks_collection.find_one({"Name": investment['asset_name']})
        if not stock:
            flash('Stock not found.', 'error')
            return redirect(url_for('dashboard'))

        # Calculate sale price and brokerage
        sale_price_per_stock = float(stock['Price'])
        total_sale_price = quantity_to_sell * sale_price_per_stock
        brokerage_charge = total_sale_price * 0.005
        final_total_sale_price = total_sale_price - brokerage_charge

        # Calculate profit/loss
        purchase_price = float(investment['price'])
        total_purchase_price = purchase_price * quantity_to_sell
        profit_loss = final_total_sale_price - total_purchase_price

        # Add the sale amount to the wallet
        user = user_collection.find_one({'username': session['username']})
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('login'))

        # Update wallet balance
        wallet_collection.update_one(
            {'user_id': user['_id']},
            {'$inc': {'balance': final_total_sale_price}},
            upsert=True  # Create a new wallet if it doesn't exist
        )

        # Add profit/loss transaction to the transactions collection
        transactions_collection.insert_one({
            'user_id': user['_id'],
            'asset_name': investment['asset_name'],
            'quantity': quantity_to_sell,
            'profit_loss': profit_loss,
            'date': datetime.now()
        })

        # Update the investment quantity
        new_quantity = investment['quantity'] - quantity_to_sell
        if new_quantity == 0:
            # If all stocks are sold, delete the investment
            investments_collection.delete_one({'_id': ObjectId(investment_id)})
        else:
            # Otherwise, update the quantity
            investments_collection.update_one(
                {'_id': ObjectId(investment_id)},
                {'$set': {'quantity': new_quantity}}
            )

        # Update the total quantity of the stock
        stocks_collection.update_one(
            {"_id": stock["_id"]},
            {"$inc": {"total_quantity": quantity_to_sell}}  # Increase total quantity
        )

        flash(f'Successfully sold {quantity_to_sell} stocks of {investment["asset_name"]} for ₹{final_total_sale_price:.2f} (after brokerage).', 'success')
        return redirect(url_for('dashboard'))

    return render_template('sell/index.html', investment=investment)

# Buy or sell bonds

@app.route('/buy_bond', methods=['GET', 'POST'])
def buy_bond():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = user_collection.find_one({'username': session['username']})
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        bond_isin = request.form.get('bond_isin').strip()  # Get ISIN from form
        quantity = int(request.form.get('quantity', 0))  # Convert to integer

        # Fetch bond details from the database
        bond = bonds_collection.find_one({"ISIN": bond_isin})
        if not bond:
            flash(f'Bond not found for ISIN: {bond_isin}', 'error')
            return redirect(url_for('buy_bond'))

        # Check if the requested quantity is available
        if bond.get("total_quantity", 0) < quantity:
            flash(f'Only {bond["total_quantity"]} bonds available for {bond["DESCRIPTOR"]}. You cannot purchase {quantity} bonds.', 'error')
            return redirect(url_for('buy_bond'))

        # Extract bond details
        bond_name = bond.get("DESCRIPTOR", "Unknown Bond")  # Bond name
        price = float(bond.get("LAST_TRADE_PRICE", 0))  # Use LAST_TRADE_PRICE
        total_price = quantity * price  # Total price
        brokerage = total_price * 0.005  # 0.5% brokerage
        final_amount = total_price + brokerage

        # Check if the user has enough tokens
        if user['tokens'] < final_amount:
            flash(f'Insufficient tokens! You need {final_amount} tokens but only have {user["tokens"]}.', 'error')
            return redirect(url_for('buy_bond'))

        # Deduct tokens from the user's account
        user_collection.update_one(
            {'_id': user['_id']},
            {'$inc': {'tokens': -final_amount}}
        )

        # Create investment record for bond
        investment = {
            'user_id': ObjectId(user['_id']),  # Convert user ID to ObjectId
            'asset_name': bond_isin,  # Store ISIN as asset_name
            'asset_type': 'Bond',  # Asset type
            'quantity': quantity,
            'price': price,
            'brokerage': brokerage,
            'total_price': total_price,
            'final_amount': final_amount,
            'date': datetime.now()
        }
        investments_collection.insert_one(investment)

        # Update the total quantity of the bond
        new_quantity = bond["total_quantity"] - quantity
        bonds_collection.update_one(
            {"ISIN": bond_isin},
            {"$set": {"total_quantity": new_quantity}}
        )

        flash(f'Bond purchased successfully! Total Amount: ₹{final_amount}', 'success')
        return redirect(url_for('dashboard'))

    # Fetch all bonds for the buy page
    bonds = list(bonds_collection.find({}, {"ISIN": 1, "DESCRIPTOR": 1, "LAST_TRADE_PRICE": 1, "total_quantity": 1}))

    # Fetch the user's current bond quantities
    user_investments = list(investments_collection.find({'user_id': ObjectId(user['_id']), 'asset_type': 'Bond'}))

    # Create a dictionary to store the user's current bond quantities
    user_bond_quantities = {}
    for investment in user_investments:
        user_bond_quantities[investment['asset_name']] = user_bond_quantities.get(investment['asset_name'], 0) + investment['quantity']

    # Pass the user's bond quantities to the template
    return render_template('buy_bond/index.html', bonds=bonds, user_bond_quantities=user_bond_quantities)

@app.route('/sell_bond/<investment_id>', methods=['GET', 'POST'])
def sell_bond(investment_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch the investment details
    investment = investments_collection.find_one({'_id': ObjectId(investment_id)})
    if not investment:
        flash('Investment not found.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Handle the sale of the bond
        quantity_to_sell = int(request.form['quantity'])  # Convert to integer

        if quantity_to_sell > investment['quantity']:
            flash('You cannot sell more bonds than you own.', 'error')
            return redirect(url_for('sell_bond', investment_id=investment_id))

        # Fetch the bond details from the bonds collection
        bond = bonds_collection.find_one({"ISIN": investment['asset_name']})  # Use ISIN to find the bond
        if not bond:
            flash('Bond not found.', 'error')
            return redirect(url_for('dashboard'))

        # Extract the bond price
        sale_price_per_bond = float(bond.get("WEIGHTED_AVERAGE_PRICE", 0))  # Use WEIGHTED_AVERAGE_PRICE
        total_sale_price = quantity_to_sell * sale_price_per_bond

        # Calculate brokerage charge (0.5% of total sale price)
        brokerage_charge = total_sale_price * 0.005

        # Calculate final total sale price after deducting brokerage
        final_total_sale_price = total_sale_price - brokerage_charge

        # Add tokens back to the user's account
        user = user_collection.find_one({'username': session['username']})
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('login'))

        user_collection.update_one(
            {'_id': user['_id']},
            {'$inc': {'tokens': final_total_sale_price}}
        )

        # Update the investment quantity
        new_quantity = investment['quantity'] - quantity_to_sell
        if new_quantity == 0:
            # If all bonds are sold, delete the investment
            investments_collection.delete_one({'_id': ObjectId(investment_id)})
        else:
            # Otherwise, update the quantity
            investments_collection.update_one(
                {'_id': ObjectId(investment_id)},
                {'$set': {'quantity': new_quantity}}
            )

        # Update the total quantity of the bond
        bonds_collection.update_one(
            {"ISIN": investment['asset_name']},
            {"$inc": {"total_quantity": quantity_to_sell}}  # Increase total quantity
        )

        flash(f'Successfully sold {quantity_to_sell} bonds of {bond["DESCRIPTOR"]} for ₹{final_total_sale_price:.2f} (after brokerage).', 'success')
        return redirect(url_for('dashboard'))

    return render_template('sell_bond/index.html', investment=investment)

# Insurance
@app.route('/buy_insurance', methods=['GET', 'POST'])
def buy_insurance():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        symbol = request.form.get('symbol').strip()  # Remove extra spaces
        quantity = int(request.form.get('quantity', 0))  # Convert to integer

        # Fetch insurance details from the database
        insurance = insurance_collection.find_one({"Symbol": symbol})
        if not insurance:
            flash(f'Insurance not found for symbol: {symbol}', 'error')
            return redirect(url_for('buy_insurance'))

        # Calculate total premium
        premium_rate = insurance['Premium_Rate']
        total_premium = premium_rate * quantity

        user = user_collection.find_one({'username': session['username']})
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('login'))

        # Check if the user has enough tokens
        if user['tokens'] < total_premium:
            flash(f'Insufficient tokens! You need {total_premium} tokens but only have {user["tokens"]}.', 'error')
            return redirect(url_for('buy_insurance'))

        # Deduct tokens from the user's account
        user_collection.update_one(
            {'_id': user['_id']},
            {'$inc': {'tokens': -total_premium}}
        )

        # Create investment record for insurance
        investment = {
            'user_id': ObjectId(user['_id']),  # Convert user ID to ObjectId
            'asset_name': symbol,  # Store symbol as asset_name
            'asset_type': 'Insurance',  # Asset type
            'quantity': quantity,
            'price': premium_rate,
            'total_price': total_premium,
            'final_amount': total_premium,
            'date': datetime.now()
        }
        investments_collection.insert_one(investment)

        flash(f'Insurance purchased successfully! Total Premium: ₹{total_premium:.2f}', 'success')
        return redirect(url_for('dashboard'))

    # Fetch all insurance policies for the buy page
    insurance_policies = list(insurance_collection.find({}, {"Symbol": 1, "Premium_Rate": 1}))
    return render_template('buy_insurance/index.html', insurance_policies=insurance_policies)

@app.route('/sell_insurance/<investment_id>', methods=['GET', 'POST'])
def sell_insurance(investment_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch the investment details
    investment = investments_collection.find_one({'_id': ObjectId(investment_id)})
    if not investment:
        flash('Investment not found.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Handle the sale of the insurance
        quantity_to_sell = int(request.form['quantity'])  # Convert to integer

        if quantity_to_sell > investment['quantity']:
            flash('You cannot sell more insurance policies than you own.', 'error')
            return redirect(url_for('sell_insurance', investment_id=investment_id))

        # Calculate the total sale price
        total_sale_price = quantity_to_sell * investment['price']

        # Add tokens back to the user's account
        user = user_collection.find_one({'username': session['username']})
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('login'))

        user_collection.update_one(
            {'_id': user['_id']},
            {'$inc': {'tokens': total_sale_price}}
        )

        # Update the investment quantity
        new_quantity = investment['quantity'] - quantity_to_sell
        if new_quantity == 0:
            # If all policies are sold, delete the investment
            investments_collection.delete_one({'_id': ObjectId(investment_id)})
        else:
            # Otherwise, update the quantity
            investments_collection.update_one(
                {'_id': ObjectId(investment_id)},
                {'$set': {'quantity': new_quantity}}
            )

        flash(f'Successfully sold {quantity_to_sell} insurance policies for ₹{total_sale_price:.2f}.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('sell_insurance/index.html', investment=investment)

def buy_stock(stock_name, quantity):
    """
    Function to buy stocks.
    """
    # Fetch stock details from the database (case-insensitive search)
    stock = stocks_collection.find_one({"Name": {"$regex": f"^{stock_name}$", "$options": "i"}})
    if not stock:
        return f"Stock {stock_name} not found."

    # Check if the requested quantity is available
    if stock.get("total_quantity", 0) < quantity:
        return f"Only {stock['total_quantity']} stocks available for {stock_name}. You cannot purchase {quantity} stocks."

    # Calculate total price and brokerage
    price = float(stock.get("Price", 0))
    total_price = quantity * price
    brokerage = total_price * 0.005  # 0.5% brokerage
    final_amount = total_price + brokerage

    # Deduct tokens from the user's account
    user = user_collection.find_one({'username': session.get('username')})
    if not user:
        return "User not found!"

    if user['tokens'] < final_amount:
        return f"Insufficient tokens! You need {final_amount} tokens but only have {user['tokens']}."

    user_collection.update_one(
        {'_id': user['_id']},
        {'$inc': {'tokens': -final_amount}}
    )

    # Create investment record
    investment = {
        'user_id': ObjectId(user['_id']),
        'asset_name': stock['Name'],  # Use stock name from database
        'asset_type': 'Stock',  # Asset type
        'quantity': quantity,
        'price': price,
        'brokerage': brokerage,
        'total_price': total_price,
        'final_amount': final_amount,
        'date': datetime.now()
    }
    investments_collection.insert_one(investment)

    # Update the total quantity of the stock
    new_quantity = stock["total_quantity"] - quantity
    stocks_collection.update_one(
        {"_id": stock["_id"]},
        {"$set": {"total_quantity": new_quantity}}
    )

    return f"Successfully bought {quantity} shares of {stock['Name']} for ₹{final_amount:.2f}."

def words_to_numbers(word):
    """
    Convert words like "five" to numbers like 5.
    """
    word_to_number = {
        "zero": 0,
        "one": 1,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
        "eight": 8,
        "nine": 9,
        "ten": 10,
        "twenty": 20,
        "thirty": 30,
        "forty": 40,
        "fifty": 50,
        "hundred": 100
    }
    return word_to_number.get(word.lower(), None)

@app.route('/voice-command', methods=['POST'])
def voice_command():
    data = request.json
    command = data.get('command')
    if not command:
        return jsonify({"error": "No command provided"}), 400

    print(f"Received command: {command}")  # Debug: Print the received command

    # Process the command using GroqCloud
    try:
        # Ask Groq to extract intent, stock name, and quantity
        groq_prompt = f"""
        Analyze the following command and extract the intent, stock name, and quantity.
        Return the response in JSON format with the following keys: "intent", "stock_name", "quantity".

        Command: "{command}"
        """

        response = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": groq_prompt,
                }
            ],
            model="mixtral-8x7b-32768",  # Use a valid model
        )

        # Extract the response
        groq_response = response.choices[0].message.content
        print(f"Groq response: {groq_response}")  # Debug: Print Groq's response

        # Parse the JSON response
        try:
            command_data = json.loads(groq_response)
        except json.JSONDecodeError:
            return jsonify({"error": "Failed to parse Groq response"}), 500

        # Extract intent, stock name, and quantity
        intent = command_data.get("intent", "").lower()
        stock_name = command_data.get("stock_name", "")
        quantity = command_data.get("quantity", 0)

        # Convert quantity to integer (if it's a word, convert it to a number)
        if isinstance(quantity, str):
            quantity = words_to_numbers(quantity)
            if quantity is None:
                return jsonify({"error": f"Invalid quantity: {quantity}"}), 400

        # Handle the intent
        if intent == "buy":
            result = buy_stock(stock_name, quantity)
            return jsonify({"response": result})
        else:
            return jsonify({"response": f"Unsupported intent: {intent}"})

    except Exception as e:
        print(f"Error processing command: {e}")  # Debug: Print any errors
        return jsonify({"error": str(e)}), 500
if __name__ == "__main__":
    app.run(debug=True)