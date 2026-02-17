// user.js
// Simple constant user module

const USERNAME = "k"; // constant username
const PASSWORD = "r"; // constant password

// Function to validate login
function validateUser(username, password) {
  return username === USERNAME && password === PASSWORD;
}

module.exports = {
  USERNAME,
  PASSWORD,
  validateUser
};
