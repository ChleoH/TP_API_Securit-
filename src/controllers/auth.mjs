import jwt from 'jsonwebtoken';
import UserModel from '../models/user.mjs';
import Validator from 'better-validator';

export default class Auth {
  constructor(app) {
    this.app = app;
    this.run();
  }

  login() {
    this.app.post('/login', async (req, res) => {
      const validator = new Validator();
      validator.object({
        name: validator.string().required(),
        password: validator.string().required()
      });
      const result = validator.validate(req.body);

      if (!result.valid) {
        return res.status(400).json({
          message: 'Invalid input',
          errors: result.errors
        });
      }

      const { name, password } = req.body;

      try {
        const user = await UserModel.findOne({ name });

        if (!user || user.password !== password) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
          { id: user._id, name: user.name, role: user.role },
          process.env.JWT_SECRET || 'efrei',
          { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.status(200).json({ token });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });
  }

  signup() {
    this.app.post('/signup', async (req, res) => {
      const validator = new Validator();
      validator.object({
        name: validator.string().minLength(3).required(),
        password: validator.string().minLength(6).required()
      });
      const result = validator.validate(req.body);

      if (!result.valid) {
        return res.status(400).json({
          message: 'Invalid input',
          errors: result.errors
        });
      }

      const { name, password, role } = req.body;

      try {
        const exists = await UserModel.findOne({ name });
        if (exists) return res.status(409).json({ message: 'User already exists' });

        const newUser = new UserModel({ name, password, role });
        await newUser.save();

        res.status(201).json({ message: 'User created successfully' });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });
  }

  // Middleware pour sécuriser les routes
  static verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
      return res.status(401).json({ message: 'Token manquant' });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET || 'efrei', (err, user) => {
      if (err) return res.status(403).json({ message: 'Token invalide' });
      req.user = user;
      next();
    });
  }

  run() {
    this.signup();
    this.login();
  }
}
