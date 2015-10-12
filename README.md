## Running the Things You See All Over App
Base assumption that you're using Vagrant or some other VM.

Once it is up and running, type **vagrant ssh**. This will log your terminal into the virtual machine, and you'll get a Linux shell prompt. When you want to log out, type **exit** at the shell prompt.  To turn the virtual machine off (without deleting anything), type **vagrant halt**. If you do this, you'll need to run **vagrant up** again before you can log into it.

Now that you have Vagrant up and running type **vagrant ssh** to log into your VM.  change to the /vagrant directory by typing **cd /vagrant**. This will take you to the shared folder between your virtual machine and host machine.

Type **ls** to ensure that you are inside the directory that contains project.py, database_setup.py, and three directories named 'static' 'templates' and 'uploads'

Type **python project.py** to run the Flask web server. In your browser visit **http://localhost:5000** to view the app.  You should be able to view, add, edit, and delete places and things you see all over those places.
