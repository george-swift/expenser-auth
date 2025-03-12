import logging
from chalice import Chalice
from chalicelib.settings import settings
from chalicelib.auth_challenges import auth_challenges
from chalicelib.auth import auth

app = Chalice(app_name=settings.cognito_app_client_name)

app.log.setLevel(logging.INFO)

app.register_blueprint(auth)

app.register_blueprint(auth_challenges)
