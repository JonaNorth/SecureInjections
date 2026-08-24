from flask import Flask, jsonify

from secureinjections.middleware.flask import InputShieldFlask

app = Flask(__name__)
InputShieldFlask(app)


@app.post("/messages")
def create_message():
    return jsonify(accepted=True)
