from dotenv import load_dotenv

from app import create_app, models

# start with python app.py, not flask run, which would skip init_db()
if __name__ == '__main__':
    # before anything reads SECRET_KEY or SEED_PASSWORD
    load_dotenv()
    app = create_app()
    models.init_db()
    models.init_uploads()
    # the debugger page lets anyone who reaches it run code
    app.run(host='127.0.0.1', port=5000, debug=False)
