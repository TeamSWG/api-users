let express = require('express')
let app = express()
let MongoClient = require('mongodb').MongoClient
let ObjectId = require('mongodb').ObjectId
let jwt = require('jsonwebtoken')

/*
 * Appropriate CORS headers are applied on all responses
 */
app.use((request, response, next) => {
	response.setHeader('Access-Control-Allow-Origin', '*')
	response.setHeader('Access-Control-Allow-Headers', 'Content-Type')
	response.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE')

	next()
})

/**
 * Browsers can send preflight checks using the OPTIONS method. We handle this by responding with HTTP OK
 */
app.options('*', (request, response) => {
	response.sendStatus(200)
})

app.use(express.json())

/**
 * Any endpoint beginning with /secure/ will be behind authentication. It is up to 
 */
app.post('/secure/*', (request, response, next) => {
	let token = request.body.token

	console.log('Secure URL hit: ' + request.url + ' with token: ' + token)

	if (!token) {
		response.sendStatus(401)
		return
	}

	jwt.verify(token, "i like pandas", { issuer: 'api-users' }, function(error, decoded) {	// HS256
		if (error) {
			console.log(error)
			response.sendStatus(500)
			return
		}

		let userId = decoded.sub

		console.log("Attempting to find user for ID: " + userId)

		// Assign a User value or something to request.user, so the secure endpoints can access a user object
		const url = 'mongodb://localhost:27017'
		const dbName = 'ditto'
	
		MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
			const db = client.db(dbName)
			const collection = db.collection('users')
	
			collection.findOne({_id: new ObjectId(userId)}, (error, result) => {
				if (error) {
					response.sendStatus(500)
				} else if (!result) {
					response.sendStatus(404)	// TODO user not found. Is 404 appropriate..?
				} else if (result.banned) {
					response.sendStatus(403)
				} else {
					request.user = result
					next()	// Pass the torch to whatever endpoint was requested
				}
			})
		})
	})
})

app.get('/users', (request, response) => {	// TODO add parameter for limiting amount of users returned
	console.log('Users requested')

	const url = 'mongodb://localhost:27017'
	const dbName = 'ditto'

	MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
		const db = client.db(dbName)
		const collection = db.collection('users')

		collection.find({}, 
		{
			fields: {
					username: 1,
					accessLevel: 1,
					banned: 1
				}
		}
		).toArray((error, result) => {
			if (error) {
				console.log(error)
				response.sendStatus(500)
			} else {
				response.contentType('application/json')
				response.send(result)
			}
			client.close()
		})
	})
})

app.get('/user/:userId', (request, response) => {
	const userId = request.params['userId']

	console.log('Information on user with ID ' + userId + ' was requested')

	if (!userId) {
		// TODO status code?
		return;
	}

	const url = 'mongodb://localhost:27017'
	const dbName = 'ditto'

	MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
		const db = client.db(dbName)
		const collection = db.collection('users')

		collection.findOne({_id: new ObjectId(userId)}, {
			fields: {
				username: 1,
				accessLevel: 1,
				banned: 1,
				characters: 1
			}
		}, (error, result) => {
			if (error) {
				response.sendStatus(500)
			} else if (!result) {
				response.sendStatus(404)
			} else {
				response.contentType('application/json')
				response.send(result)
			}
		})
	})
})

app.post('/user/create', (request, response) => {
	console.log("User creation requested")
	var userCreation = request.body;

	const url = 'mongodb://localhost:27017'
	const dbName = 'ditto'

	MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
		const db = client.db(dbName)
		const collection = db.collection('users')

		// TODO check that username isn't in use. If it is, return HTTP 403

		collection.insert({
			username: userCreation.username,
			password: userCreation.password,	// TODO hashed
			accessLevel: 'player',
			banned: false,
			characters: []
		}, (error, result) => {
			if (error) {
				response.sendStatus(409)	// Duplicate resource
			} else {
				console.log("User " + userCreation.username + " succesfully inserted into users collection")
				response.sendStatus(200)
			}
		});

		client.close()
	});
});

app.post('/user/login', (request, response) => {
	const username = request.body.username;
	const password = request.body.password;
	const url = 'mongodb://localhost:27017'
	const dbName = 'ditto'

	console.log('Login attempt ' + username + ":" + password);

	MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
		const db = client.db(dbName)
		const collection = db.collection('users')

		collection.findOne({username, password}, { fields: {_id: 1, banned: 1} }, (error, result) => {
			if (error) {
				response.sendStatus(500)
			} else if (!result) {
				response.sendStatus(404)
			} else if (result.banned) {
				response.sendStatus(403)
			} else {
				response.contentType('application/json')

				let subject = result._id
				response.send({
					user: result,
					token: jwt.sign({}, 'i like pandas', {subject: result._id.toString(), issuer: 'api-users'})
				})
			}
		})
	})
})

app.post('/secure/user/delete/:userId', (request, response) => {
	const user = request.user;	// The user wanting to delete a user. TODO permission check on accessLevel
	const userId = request.params['userId']	// The ID for the user we should delete

	if (user.accessLevel === 'player') {	// TODO this is pretty crude
		response.sendStatus(403)
		return;
	}

	if (userId === user._id) {
		// We can't delete ourselves
		response.sendStatus(400)
		return;
	}

	console.log('Delete attempt: ' + userId + ' from ' + user.username);

	const url = 'mongodb://localhost:27017'
	const dbName = 'ditto'

	MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
		const db = client.db(dbName)
		const collection = db.collection('users')

		collection.deleteOne({_id: new ObjectId(userId)}, (error, result) => {
			if (error) {
				response.sendStatus(500)
			} else if (!result) {
				response.sendStatus(404)
			} else {
				response.sendStatus(200);
			}
		})
	})
})

app.post('/secure/user/accessLevel/:userId', (request, response) => {
	const user = request.user;	// The user wanting to edit the access level of another user
	const userId = request.params['userId']	// The ID for the user we edit the access level of
	const accessLevel = request.body.accessLevel;

	if (user.accessLevel === 'player') {	// TODO this is pretty crude
		response.sendStatus(403)
		return;
	}

	if (userId === user._id.toString()) {
		// We can't edit our own access level
		response.sendStatus(400)
		return;
	}

	if (!accessLevel) {
		response.sendStatus(400);
		return;
	}

	console.log('Access level change attempt for : ' + userId + ' from ' + user.username);

	const url = 'mongodb://localhost:27017'
	const dbName = 'ditto'

	MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
		const db = client.db(dbName)
		const collection = db.collection('users')

		collection.updateOne({_id: new ObjectId(userId)}, {$set: { accessLevel }}, (error, result) => {
			if (error) {
				response.sendStatus(500)
			} else if (!result) {
				response.sendStatus(404)
			} else {
				response.sendStatus(200);
			}
		})
	})
})

app.post('/secure/user/ban/:userId', (request, response) => {
	const user = request.user;	// The user wanting to edit the access level of another user
	const userId = request.params['userId']	// The ID for the user we edit the access level of
	const banned = request.body.banned ? true : false;

	if (user.accessLevel === 'player') {	// TODO this is pretty crude
		response.sendStatus(403)
		return;
	}

	if (userId === user._id) {
		// We can't ban ourselves
		response.sendStatus(400)
		return;
	}

	console.log('Ban attempt for : ' + userId + ' from ' + user.username);

	const url = 'mongodb://localhost:27017'
	const dbName = 'ditto'

	MongoClient.connect(url, {useNewUrlParser: true}, (err, client) => {
		const db = client.db(dbName)
		const collection = db.collection('users')

		collection.updateOne({_id: new ObjectId(userId)}, {$set: { banned }}, (error, result) => {
			if (error) {
				response.sendStatus(500)
			} else if (!result) {
				response.sendStatus(404)
			} else {
				response.sendStatus(200);
			}
		})
	})
})

app.listen(3000, () => console.log('Listening on port 3000'))	// TODO configurable port