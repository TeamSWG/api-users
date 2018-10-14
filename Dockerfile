FROM node:10.12.0-slim

# 1. Transfer source files to the image
ADD app.js /app.js
ADD package.json /package.json

# 2. Install dependencies defined in package.json
RUN npm install

# 3. Fetch the HS256 secret
ARG jwt_secret

# 4. Set an environment variable as the secret, so we can fetch it later
ENV jwt_secret ${jwt_secret}

# When running the image, use node to run app.js
CMD node app.js 3000 ${jwt_secret}