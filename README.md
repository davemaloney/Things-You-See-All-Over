# Things You See All Over

Base assumption that you're using Vagrant or some other VM forwarding to port 8000.

## Get virtual box up and running
Assuming vagrant, once it is up and running (`vagrant up`), type `vagrant ssh` to log your terminal into the virtual machine, and you'll get a Linux shell prompt. 
+ **EXIT** When you want to log out, type `exit` at the shell prompt 
+ **POWER DOWN** To turn the virtual machine off (without deleting anything), type `vagrant halt`

## Start the App
Change to the `/vagrant` directory by typing `cd /vagrant`. This will take you to the shared folder between your virtual machine and host machine.

Type `ls` to ensure that you are inside the directory that contains 
```
catalog
├── client_secrets/       # Expected to contain files from Facebook, Google, and GitHub
├── static/
│   ├── css/
│   ├── fonts/
│   └── js/
├── templates/
│   ├── components/
│   ├── places/
│   ├── things/
│   └── main.html
├── uploads/
├── .gitignore
├── database_setup.py
├── pg_config.sh
├── project.py
└── README.md
```
+ Run `sh pg_config.sh` to ensure dependencies
+ Run `python project.py` to run the Flask web server 
+ In your browser visit [http://localhost:8000]() to view the app.

## Use the App
You should be able to view, add, edit, and delete places and things you see all over those places.

## Dependencies

### Backend
+ apt-get
  + postgresql
  + python-psycopg2
  + python-sqlalchemy
  + python-pip
+ pip 
  + werkzeug==0.8.3
  + flask==0.9
  + Flask-Login==0.1.3
  + oauth2client
  + requests
  + httplib2

### Frontend
+ Bootstrap v3.3.5
+ jQuery v1.11.3