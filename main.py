from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
import io
import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = "users"
COURSES = 'courses'
PHOTO_BUCKET = 'assignment6-user-avatars'

# Update the values of the following 3 variables
CLIENT_ID = '8UyEmVxgHS3l3f9hoP2ucBUovBVoNyel'
CLIENT_SECRET = 'qW5qOSnLEZ7S7dBbNTJ08yzJ1AZyiNE1MLUODMDISHt0xPPl9ncLaCu60UfR-XxE'
DOMAIN = 'dev-0epwtaura47c4vnu.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

# PASSWORD: CheeseLovers123

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    try:
        content = request.get_json()
        username = content["username"]
        password = content["password"]
        body = {'grant_type':'password','username':username,
                'password':password,
                'client_id':CLIENT_ID,
                'client_secret':CLIENT_SECRET
                }
        headers = { 'content-type': 'application/json' }
        url = 'https://' + DOMAIN + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)

        if r.status_code != 200:
            return {'Error': 'Unauthorized'}, 401

        data = r.json()
        token = data['id_token']
        return {'token': token}, 200, {'Content-Type':'application/json'}

    except Exception:
        return {'Error': 'The request body is invalid'}, 400




#### GET USERS, ADMIN ONLY #### might need a try for making sure they are admins?
@app.route('/users', methods=['GET'])
def users_get():
    try:
        payload = verify_jwt(request)
        checker = client.query(kind=USERS)
        checker.add_filter('role', '=', 'admin')
        admins = list(checker.fetch())
        for item in admins:
            if item['sub'] == payload['sub']:
                query = client.query(kind=USERS)
                results = list(query.fetch())
                allusers = []
                for r in results:
                    r['id'] = r.key.id
                    allusers.append(r)
                return allusers, 200
            
        return {'Error': 'You don\'t have permission on this resource'}, 403
    
    except Exception:
        return {'Error': 'Unauthorized'}, 401


#### Get A User by id, ADMIN or own user getting its info ####
@app.route('/users/<int:id>', methods=["GET"])
def get_user_by_id(id):
    try:
        payload = verify_jwt(request)
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        if user['sub'] == payload['sub'] or user['role'] == 'admin': 
            user['id'] = user.key.id
            # check for avatar & add if there
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(PHOTO_BUCKET)
            file_name = str(user['id']) + '.png'
            blob = bucket.blob(file_name)
            if blob.exists():
                user['avatar_url'] = request.base_url + '/avatar'
            
            if user['role'] == 'student' or user['role'] == 'instructor':
                courses = []
                user['courses'] = courses

            return user, 200
        else:
            return {'Error': 'You don\'t have permission on this resource'}, 403
    except Exception:
        return {'Error': 'Unauthorized'}, 401   


#### Post/Update User avatar ####
@app.route('/users/<int:id>/avatar', methods=['POST'])
def send_user_avatar(id):
    try:
        # Check if there is an entry in request.files with the key 'file'
        if 'file' not in request.files:
            return ({'Error': 'The request body is invalid'}, 400)
        # Set file_obj to the file sent in the request
        file_obj = request.files['file']

        # get & verify the user
        payload = verify_jwt(request)
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        if user['sub'] != payload['sub']:
            return {'Error': 'You don\'t have permission on this resource'}, 403

        # Change name for accessing purposes
        file_obj.filename = str(id) + '.png'

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(file_obj.filename)
        file_obj.seek(0)
        blob.upload_from_file(file_obj)

        url = request.base_url 

        return ({'avatar_url': url},200)
    
    except Exception:
        return {'Error': 'Unauthorized'}, 401 

#### GET user avatar ####
@app.route('/users/<int:id>/avatar', methods=['GET'])
def get_user_avatar(id):
    try:
        payload = verify_jwt(request)
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        if user['sub'] != payload['sub']:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        # Create a blob with the given file name
        file_name = str(id) + '.png'
        blob = bucket.blob(file_name)

        if not blob.exists():
            return {'Error': 'Not found'}, 404
        # Create a file object in memory using Python io package
        file_obj = io.BytesIO()
        # Download the file from Cloud Storage to the file_obj variable
        blob.download_to_file(file_obj)
        # Position the file_obj to its beginning
        file_obj.seek(0)
        # Send the object as a file in the response with the correct MIME type and file name
        return send_file(file_obj, mimetype='image/x-png', download_name=file_name)

    except Exception:
        return {'Error': 'Unauthorized'}, 401 


#### DELETE user avatar ####
@app.route('/users/<int:id>/avatar', methods=['DELETE'])
def delete_avatar(id):
    try:
        payload = verify_jwt(request)
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        if user['sub'] != payload['sub']:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        file_name = str(id) + '.png'
        blob = bucket.blob(file_name)

        if not blob.exists():
            return {'Error': 'Not found'}, 404
        # Delete the file from Cloud Storage
        blob.delete()
        return '',204
    
    except Exception:
        return {'Error': 'Unauthorized'}, 401 


#### POST a course, ADMIN only ####
@app.route('/courses', methods=['POST'])
def post_course():
    try:
        # check payload
        payload = verify_jwt(request)
        
        checker = client.query(kind=USERS)
        checker.add_filter('role', '=', 'admin')
        admins = list(checker.fetch())
        for item in admins: # check for matching admin
            if item['sub'] == payload['sub']: # matching admin can perform actions
                # check post body
                content = request.get_json()
                user_key = client.key(USERS, content['instructor_id'])
                instructor = client.get(key=user_key)
                if len(content) != 5 or instructor is None or instructor['role'] != 'instructor':
                    return {"Error": "The request body is invalid"}, 400
                
                new_course = datastore.entity.Entity(key=client.key(COURSES))
                new_course.update({
                    "instructor_id": content['instructor_id'],
                    "number": content['number'],
                    "subject": content['subject'],
                    "term": content['term'],
                    "title": content['title'],
                })
                client.put(new_course)

                new_course['id'] = new_course.key.id
                url = request.base_url
                url += '/' + str(new_course['id'])
                new_course['self'] = url

                return new_course, 201
            
        return {'Error': 'You don\'t have permission on this resource'}, 403

    except Exception:
        return {'Error': 'Unauthorized'}, 401 


#### GET all courses, no access restrictions ####
@app.route('/courses', methods=['GET'])
def get_courses():
    query_params = request.args
    courses = []
    ulimit = 3
    uoffset = 0
    if 'offset' and 'limit' in query_params:
        ulimit = int(query_params['limit'])
        uoffset = int(query_params['offset'])

    query = client.query(kind=COURSES)
    query.order = ['subject']
    course_query = query.fetch(limit=ulimit, offset=uoffset)

    for course in course_query:
        course['id'] = course.key.id
        course['self'] = request.base_url + '/' + str(course['id'])
        courses.append(course)

    results = {}
    next = request.base_url + '?offset=' + str(uoffset + ulimit) + '&limit=' + str(ulimit)

    results['courses'] = courses
    results['next'] = next

    return results, 200


#### GET a course by id, no restrictions ####
@app.route('/courses/<int:id>', methods=['GET'])
def get_course_byid(id):
    user_key = client.key(COURSES, id)
    course = client.get(key=user_key)

    if course is None:
        return {'Error': 'Not found'}, 404
    
    course['id'] = course.key.id
    course['self'] = request.base_url

    return course, 200


#### PATCH a course ####
@app.route('/courses/<int:id>', methods=['PATCH'])
def patch_course(id):
    try:
        # check payload
        payload = verify_jwt(request)
        
        checker = client.query(kind=USERS)
        checker.add_filter('role', '=', 'admin')
        admins = list(checker.fetch())
        for item in admins: # check for matching admin
            if item['sub'] == payload['sub']: # matching admin can perform actions
                content = request.get_json()

                course_key = client.key(COURSES, id)
                course = client.get(key=course_key)

                course.update(content)

                user_key = client.key(USERS, course['instructor_id'])
                instructor = client.get(key=user_key)
                if instructor is None or instructor['role'] != 'instructor' or not content:
                    return {"Error": "The request body is invalid"}, 400
                
                client.put(course)

                course['id'] = course.key.id
                url = request.base_url
                url += '/' + str(course['id'])
                course['self'] = url

                return course, 201
            
        return {'Error': 'You don\'t have permission on this resource'}, 403

    except Exception:
        return {'Error': 'Unauthorized'}, 401 



#### DELETE course by id, ADMIN only ####
@app.route('/courses/<int:id>', methods=['DELETE'])
def delete_course(id):
    try:
        # check payload
        payload = verify_jwt(request)
        
        checker = client.query(kind=USERS)
        checker.add_filter('role', '=', 'admin')
        admins = list(checker.fetch())
        for item in admins: # check for matching admin
            if item['sub'] == payload['sub']: # matching admin can perform actions

                course_key = client.key(COURSES, id)
                course = client.get(key=course_key)
                
                if course is None:
                    break

                client.delete(course)

                course['id'] = course.key.id
                url = request.base_url
                url += '/' + str(course['id'])
                course['self'] = url

                return course, 201
            
        return {'Error': 'You don\'t have permission on this resource'}, 403

    except Exception:
        return {'Error': 'Unauthorized'}, 401 


#### UPDATE user enrollment ####
@app.route('/' + COURSES + '/<int:id>/' + USERS, methods=['PATCH'])
def update_enrollment(id):
    try:
        payload = verify_jwt(request)
        user_id = payload.get('sub')

        # Get course
        course_key = client.key(COURSES, id)
        course = client.get(key=course_key)

        if course is None:
            return {"Error": "You don\'t have permission on this resource"}, 403

        if 'enrollment' not in course:
            course['enrollment'] = []

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', user_id)
        results = list(query.fetch())

        if not results or results[0]['role'] not in ['admin', 'instructor']:
            return {"Error": "You don\'t have permission on this resource"}, 403

        # Get request content
        content = request.get_json()
        students_to_add = content.get('add', [])
        students_to_remove = content.get('remove', [])

        error = set(students_to_add) & set(students_to_remove)
        if error:
            return {"Error": "Enrollment data is invalid"}, 409

        if students_to_add:
            add_students = []

            # Validate if the student IDs exists
            for student in students_to_add:
                student_key = client.key(USERS, student)
                result = client.get(student_key)

                # If student exists
                if result:
                    add_students.append(student)
                else: 
                    return {"Error": "Enrollment data is invalid"}, 409

            for student in add_students:
                # Skip students that are already in the course
                if student not in course['enrollment']:
                    course['enrollment'].append(student)
        
        if students_to_remove:
            remove_students = []

            # Validate if the student IDs exists
            for student in students_to_remove:
                student_key = client.key(USERS, student)
                result = client.get(student_key)

                if results:
                    remove_students.append(student)
                else:
                    return {"Error": "Enrollment data is invalid"}, 409

            # Drop students
            for student in remove_students:
                # Skip students not enrolled in the course
                if student in course['enrollment']:
                    course['enrollment'].remove(student)

        client.put(course)

        return '', 200 
    except:
        return {"Error": "Unauthorized"}, 401


#### GET course enrollment ####
@app.route('/' + COURSES + '/<int:id>/' + USERS, methods=['GET'])
def get_enrollment(id):
    if request.method == 'GET':
        try:
            payload = verify_jwt(request)
            user_id = payload.get('sub')

            # Get course
            course_key = client.key(COURSES, id)
            course = client.get(key=course_key)

            if course is None:
                return {"Error": "You don\'t have permission on this resource"}, 403

            query = client.query(kind=USERS)
            query.add_filter('sub', '=', user_id)
            results = list(query.fetch())

            if not results or results[0]['role'] not in ['admin', 'instructor']:
                return {"Error": "You don\'t have permission on this resource"}, 403

            if course.get('enrollment'):
                students = course['enrollment']
            else:
                students = []

            return students, 200 
        except:
            return {"Error": "Unauthorized"}, 401



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

