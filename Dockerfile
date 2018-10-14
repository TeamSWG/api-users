FROM node:10.12.0-slim

# 1. Transfer source files to the image
ADD app.js /app.js
ADD package.json /package.json

# 2. Install dependencies defined in package.json
RUN npm install

# When running the image, use node to run app.js
CMD node app.js $node_port $jwt_secret