#Project Overview

You will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

#Project Overview

You will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

#What Will I Learn?

You will learn how to develop a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication. You will then learn when to properly use the various HTTP methods available to you and how these methods relate to CRUD (create, read, update and delete) operations.

# Required software

Vagrant and VirtualBox are needed to be installed before running the program. Vagrant can be downloaded from HashiCorp [website](https://www.vagrantup.com/), and VirtualBox from [here](https://www.virtualbox.org/).

# How to start

* After the installation, download Vagrant Virtual Machine from [here](https://github.com/udacity/fullstack-nanodegree-vm)
* `cd` To the directory you have placed the clone/extract.
* Launch the Virtual Machine by running in command line" `vagrant up`
* Enter  your Virtual Machine after the previous command: `vagrant ssh`
* Clone / extract this project the `catalog` directory in your vagrant folder
* Enter this repository by running the following command:
        `cd /vagrant/catalog`
* Create the database by running:
        `python db_setup.py`
* Insert database records with the following command:
        `python db_insert_records.py`
* Run the python script `project.py` with the following command:
        `python project.py`
* Open the application by visiting `http://localhost:8000/` in any browser.

# Project Structure

* Templates folder has master.html which is the primary layout document that is included in all the views.
* Templates folder has header.html which is included in all the views and displays the header menu. 

## References
https://github.com/udacity/APIs/tree/master/Lesson_4/10_Adding%20OAuth%202.0%20for%20Authentication
https://github.com/udacity/OAuth2.0
