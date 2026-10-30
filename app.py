
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

import pickle
import re
import os
import sqlite3
import csv
import io
import hmac

from datetime import datetime
from functools import wraps


# ==========================================
# 1. FLASK APPLICATION CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "Dev-only-change-this-secret"
)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


# ==========================================
# 2. DATABASE CONFIGURATION
# ==========================================

os.makedirs("instance", exist_ok=True)

DATABASE = os.path.join(
    "instance",
    "feedback.db"
)


# ==========================================
# 3. ADMIN PASSWORD
# ==========================================

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")


# ==========================================
# 4. LOAD MACHINE LEARNING MODEL
# ==========================================

try:

    with open("vectorizer.pkl", "rb") as file:
        vectorizer = pickle.load(file)

    with open("phishing.pkl", "rb") as file:
        model = pickle.load(file)

    print("ML model loaded successfully!")
    print("Vectorizer loaded successfully!")

except Exception as e:

    raise RuntimeError(
        f"Error loading model or vectorizer: {e}"
    )


# ==========================================
# 5. INITIALIZE DATABASE
# ==========================================

def init_db():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT NOT NULL,

            predicted_label TEXT NOT NULL,

            corrected_label TEXT NOT NULL,

            is_correct INTEGER NOT NULL,

            timestamp TEXT NOT NULL

        )
    """)

    conn.commit()

    conn.close()

    print("Database initialized successfully!")


# ==========================================
# 6. SAVE USER FEEDBACK
# ==========================================

def save_feedback(
    url,
    predicted_label,
    corrected_label
):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    is_correct = int(
        predicted_label == corrected_label
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO feedback (

            url,
            predicted_label,
            corrected_label,
            is_correct,
            timestamp

        )

        VALUES (?, ?, ?, ?, ?)

    """, (
        url,
        predicted_label,
        corrected_label,
        is_correct,
        timestamp
    ))

    conn.commit()

    conn.close()


# ==========================================
# 7. HOME PAGE AND URL DETECTION
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():

    prediction = ""

    url = ""

    predicted_label = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        # Validate URL input

        if not url or len(url) > 2048:

            prediction = "Please enter a valid URL."

        else:

            try:

                # Remove HTTP, HTTPS and WWW

                cleaned_url = re.sub(
                    r"^https?://(www\.)?",
                    "",
                    url,
                    flags=re.IGNORECASE
                )

                # Transform URL using TF-IDF vectorizer

                transformed_url = vectorizer.transform(
                    [cleaned_url]
                )

                # Predict using trained ML model

                predicted = model.predict(
                    transformed_url
                )[0]

                print("Prediction:", predicted)

                raw_label = str(
                    predicted
                ).strip().lower()

                # Phishing classification

                if raw_label in ["bad", "0"]:

                    predicted_label = "phishing"

                    prediction = (
                        "Warning! This is a phishing website."
                    )

                # Legitimate classification

                elif raw_label in ["good", "1"]:

                    predicted_label = "legitimate"

                    prediction = (
                        "This website is classified as legitimate."
                    )

                else:

                    prediction = (
                        f"Unknown prediction result: {predicted}"
                    )

            except Exception as e:

                print("Prediction error:", e)

                prediction = (
                    "An error occurred while analyzing the URL."
                )

    return render_template(
        "index.html",
        prediction=prediction,
        url=url,
        predicted_label=predicted_label
    )


# ==========================================
# 8. USER FEEDBACK ROUTE
# ==========================================

@app.route("/feedback", methods=["POST"])
def feedback():

    url = request.form.get(
        "url",
        ""
    ).strip()

    predicted_label = request.form.get(
        "predicted_label",
        ""
    ).strip()

    corrected_label = request.form.get(
        "corrected_label",
        ""
    ).strip()

    allowed_labels = [
        "phishing",
        "legitimate"
    ]

    # Validate URL

    if not url or len(url) > 2048:

        flash("Invalid URL.")

        return redirect(
            url_for("index")
        )

    # Validate predicted label

    if predicted_label not in allowed_labels:

        flash("Invalid prediction label.")

        return redirect(
            url_for("index")
        )

    # Validate corrected label

    if corrected_label not in allowed_labels:

        flash("Please select a valid correction.")

        return redirect(
            url_for("index")
        )

    try:

        save_feedback(
            url,
            predicted_label,
            corrected_label
        )

        flash(
            "Thank you! Your feedback has been saved successfully."
        )

    except Exception as e:

        print("Feedback error:", e)

        flash(
            "Unable to save feedback."
        )

    return redirect(
        url_for("index")
    )


# ==========================================
# 9. ADMIN AUTHENTICATION DECORATOR
# ==========================================

def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin_login")
            )

        return function(*args, **kwargs)

    return wrapper


# ==========================================
# 10. ADMIN LOGIN
# ==========================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if (
            ADMIN_PASSWORD
            and hmac.compare_digest(
                password,
                ADMIN_PASSWORD
            )
        ):

            session.clear()

            session["admin_logged_in"] = True

            return redirect(
                url_for("admin_feedback")
            )

        flash(
            "Incorrect admin password."
        )

    return render_template(
        "admin_login.html"
    )


# ==========================================
# 11. ADMIN FEEDBACK DASHBOARD
# ==========================================

@app.route("/admin/feedback")
@admin_required
def admin_feedback():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *

        FROM feedback

        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    conn.close()

    return render_template(
        "admin_feedback.html",
        records=records
    )


# ==========================================
# 12. EXPORT FEEDBACK TO CSV
# ==========================================

@app.route("/admin/export-feedback")
@admin_required
def export_feedback():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT

            id,
            url,
            predicted_label,
            corrected_label,
            is_correct,
            timestamp

        FROM feedback

        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    conn.close()

    # Create CSV file in memory

    output = io.StringIO()

    writer = csv.writer(output)

    # CSV headings

    writer.writerow([

        "ID",
        "URL",
        "Predicted Label",
        "Corrected Label",
        "Prediction Correct",
        "Timestamp"

    ])

    # Write feedback records

    writer.writerows(records)

    # Convert CSV to downloadable file

    csv_data = io.BytesIO(

        output.getvalue().encode(
            "utf-8-sig"
        )

    )

    return send_file(

        csv_data,

        mimetype="text/csv",

        as_attachment=True,

        download_name="phishing_feedback.csv"

    )


# ==========================================
# 13. ADMIN LOGOUT
# ==========================================

@app.route("/admin/logout")
@admin_required
def admin_logout():

    session.clear()

    flash(
        "Admin logged out successfully."
    )

    return redirect(
        url_for("admin_login")
    )


# ==========================================
# 14. ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def page_not_found(error):

    return "Page not found.", 404


@app.errorhandler(413)
def file_too_large(error):

    return "Request is too large.", 413


# ==========================================
# 15. RUN FLASK APPLICATION
# ==========================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
