from flask import Flask, session

app = Flask(__name__)
# Простий секретний ключ, необхідний для роботи сесій у Flask
app.secret_key = "super-secret-key-for-baseline"

@app.route("/login", methods=["POST"])
def login():
    session["x"] = 1
    return "Logged in (Flask Plain)"

if __name__ == "__main__":
    app.run(port=5201, debug=True)