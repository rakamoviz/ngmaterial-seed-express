var UserRepository = require("./user-repository.js")
var _ = require("lodash")
  
module.exports = Promise.all([
  UserRepository.create("bob@email.com", "password_bob"),
  UserRepository.create("alice@email.com", "password_alice")
]).then(users => {  
  return Promise.all(_.map(users, user => UserRepository.save(user)))
})

