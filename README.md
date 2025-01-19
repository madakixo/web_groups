# web_groups
create simple flask web app for social group
*1st commit* 

###Notes:
#### Database: This setup uses SQLite for simplicity, but for 19,999 groups and more interactions, 
              
              `app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'`
              `app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False`
              `#function call `
              `db = SQLAlchemy(app)`


              
#### Security: The example includes basic password hashing but lacks comprehensive security measures. 

#### Authentication, authorization, and session management would need to be implemented for real-world use.
##### Profile Images: This skeleton does not handle file uploads for profile images. You would need to 
implement file handling and storage.
##### Scalability: For this scale of users and groups, consider using a microservices architecture or at 
least optimizing your SQL queries and indexes.

*This structure gives you a basic framework to expand upon for your specific requirements. 
Remember to handle errors, implement proper user authentication, and ensure database performance 
with such a large number of groups and posts.*
