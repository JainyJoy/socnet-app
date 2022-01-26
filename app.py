from flask import Flask
from flask.blueprints import Blueprint
from flask_cors import CORS
import routes
import config
from flask_mail import Mail
import logging


logging.basicConfig(filename='info.log',
level=logging.DEBUG,
format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

log = logging.getLogger('file')


app = Flask(__name__)


app.config.update(config.MAIL_SETTINGS)
#creating an instance of Mail class
mail=Mail(app)



if config.ENABLE_CORS:
    cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

for blueprint in vars(routes).values():
    if isinstance(blueprint, Blueprint):
        app.register_blueprint(blueprint, url_prefix=config.CONTEXT_PATH)

if __name__ == "__main__":
    log.info('starting server at {} at port {}'.format(
        config.HOST, config.PORT))
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG,threaded=True)
