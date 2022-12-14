"use strict";

const mongoose = require("mongoose");
const bcrypt = require('bcrypt');

const usuarioSchema = mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
});

// método estáico
usuarioSchema.statics.hashPassword = function(passwordEnClaro) {
  return bcrypt.hash(passwordEnClaro, 7);
}

// método de instancia
usuarioSchema.methods.comparePassword = function(passwordEnClaro) {
  return bcrypt.compare(passwordEnClaro, this.password);
}

const Usuario = mongoose.model("Usuario", usuarioSchema);

module.exports = Usuario;
