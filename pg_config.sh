apt-get -qqy update
apt-get -qqy install postgresql python-psycopg2
apt-get -qqy install python-sqlalchemy
apt-get -qqy install python-pip
pip install --user werkzeug==0.8.3
pip install --user flask==0.9
pip install --user Flask-Login==0.1.3
pip install --user oauth2client
pip install --user requests
pip install --user httplib2
pip install --user sqlalchemy
