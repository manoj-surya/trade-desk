import os
import datetime
import re
from flask import jsonify
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Retrieve user's cash balance
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Retrieve user's stock holdings and calculate their total values
    rows = db.execute("""
        SELECT symbol, SUM(shares) as total_shares
        FROM account
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, user_id)

    stocks = []
    grand_total = user_cash

    for row in rows:
        symbol = row["symbol"]
        shares = row["total_shares"]

        # Lookup current price of the stock
        quote = lookup(symbol)
        if quote is None:
            continue

        price = quote["price"]
        total_value = shares * price

        # Add stock data to the list
        stocks.append({
            "symbol": symbol,
            "shares": shares,
            "price": price,
            "total_value": total_value
        })

        # Add stock's total value to the grand total
        grand_total += total_value

    return render_template("index.html", stocks=stocks, cash=usd(user_cash), grand_total=usd(grand_total))



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        symbol=request.form.get("symbol")
        shares=request.form.get("shares")

        # Validate user input
        if not symbol:
            return apology("Symbol cannot be blank")

        try:
            shares = int(shares)
            if shares <= 0:
                raise ValueError
        except ValueError:
            return apology("Enter a valid number of shares")

        quote = lookup(symbol.upper())

        if quote == None:
            return apology("Enter valid symbol")

        price = quote["price"]
        buy_value = shares * price

        user_id = session["user_id"]
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        if buy_value > user_cash:
            return apology("Insufficient funds")

        # Deduct the buy_value from user's cash and update the user's cash in the database
        updated_cash = user_cash - buy_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)
        username=db.execute("SELECT username FROM users WHERE id= ?",user_id)[0]["username"]

        # Perform the rest of the buy transaction and update the user's account history
        date=datetime.datetime.now()
        db.execute("INSERT INTO account (symbol, shares, price, date, name,user_id) VALUES (?,?, ?, ?, ?, ?)",
           quote["symbol"], shares, quote["price"], date, username,user_id)

        db.execute("INSERT INTO history (user_id, symbol, shares, price, transaction_type,date) VALUES (?,?, ?, ?, ?, ?)",
                   user_id, quote["symbol"], shares, quote["price"], "BUY",date)

        flash("Buy confirmed")

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    # Retrieve all of the user's transactions from the database
    transactions = db.execute("""
        SELECT symbol, shares, price, transaction_type, date
        FROM history
        WHERE user_id = ?
        ORDER BY date DESC
    """, user_id)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    else:
        symbol= request.form.get("symbol")
        quote = lookup(symbol.upper())

        if quote == None:
            return apology("Enter valid symbol")

        else:
            return render_template("quoted.html",name=quote["name"],price=quote["price"],symbol=quote["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    else:
        username=request.form.get("username")
        password=request.form.get("password")
        confirmation=request.form.get("confirmation")

        # Validate user input
        if not username:
            return apology("Username cannot be blank")

        # Check if the username already exists in the database
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("Username already exists")

        if not password:
            return apology("Password cannot be blank")

        if password != confirmation:
            return apology("Passwords do not match")

        if not re.search(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]+$", password):
            return apology("Password must contain at least one letter, one number, and one symbol")

        # Hash the user's password
        hashed_password = generate_password_hash(password)

        # Insert the new user into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        # Retrieve the user id of the inserted user
        new_user = db.execute("SELECT last_insert_rowid() AS id FROM users")[0]["id"]

        # Remember which user has logged in
        session["user_id"] = new_user

        # Redirect user to home page
        return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        # Get the symbols of stocks that the user owns
        user_id = session["user_id"]
        stocks = db.execute("SELECT symbol FROM account WHERE user_id = ?", user_id)

        return render_template("sell.html", stocks=stocks)


    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validate user input
        if not symbol:
            return apology("Please select a stock")

        if not shares:
            return apology("Please enter the number of shares to sell")

        try:
            shares = int(shares)
        except ValueError:
            return apology("Please enter a valid number of shares")

        if shares <= 0:
            return apology("Please enter a positive number of shares")

        # Check if the user owns the selected stock
        user_id = session["user_id"]
        rows = db.execute("SELECT * FROM account WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if len(rows) != 1 or rows[0]["shares"] < shares:
            return apology("You do not own enough shares of the selected stock")

        # Lookup the current price of the stock
        quote = lookup(symbol)
        if not quote:
            return apology("Failed to get stock quote")

        price = quote["price"]
        sell_value = shares * price

        # Update the user's portfolio and cash balance
        db.execute("UPDATE account SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, user_id, symbol)
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sell_value, user_id)

        date=datetime.datetime.now()
        # Insert the transaction into the history table
        db.execute("INSERT INTO history (user_id, symbol, shares, price, transaction_type,date) VALUES (?, ?, ?, ?, ?,?)",
                   user_id, symbol, shares, price, "SELL",date)

        flash("Sell confirmed")
        return redirect("/")

if __name__=='__main__':
    app.run(host="0.0.0.0",port=5000,debug=False)
