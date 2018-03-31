const bcrypt = require('bcryptjs');
const uuidv4 = require('uuid/v4');
const _ = require('lodash');

class User {
  constructor(email, password, _id) {
    this.email = email;
    this.password = password
    if (_id) {
      this._id = _id
    } else {
      this._id = uuidv4()
    }
  }

  comparePassword(password) {
    return new Promise((resolve, reject) => {
      bcrypt.compare(password, this.password, function(err, isMatch) {
        if (err) return reject(err)
        resolve(isMatch);
      });
    })
  }
}

let existingUsers = [];
let currentOp = Promise.resolve(true)
function create(email, password) {
  return new Promise((resolve, reject) => {
    bcrypt.genSalt(10, function(err, salt) {
      bcrypt.hash(password, salt, function(err, hashedPassword) {
        if (err) return reject(err)
        resolve (new User(email, hashedPassword))
      });
    });
  })
}

function save(user) {
  currentOp = currentOp.then(() => {
    const existingUser = _.find(existingUsers, existingUser => {
      return existingUser._id == user._id
    })
  
    if (existingUser) {
      //update
      const updatedExistingUsers = _.filter(
        existingUsers, existingUser => existingUser._id != user._id
      )
      updatedExistingUsers.push(_.clone(user))
      existingUsers = updatedExistingUsers
    } else {
      //insert
      existingUsers.push(_.clone(user))
    }
  })

  return currentOp
}

function findById(_id) {
  currentOp = currentOp.then(() => {
    return _.chain(existingUsers).find(existingUser => {
      return existingUser._id == _id
    }).clone().value()
  })

  return currentOp
}

function findOne(matcher) {
  currentOp = currentOp.then(() => {
    return _.chain(existingUsers).find(existingUser => {
      const existingUserProps = _.pick(existingUser, _.keys(matcher))
      return _.isEqual(matcher, existingUserProps)
    }).clone().value()
  })

  return currentOp
}

module.exports = {
  create: create,
  save: save,
  findById: findById,
  findOne: findOne
}