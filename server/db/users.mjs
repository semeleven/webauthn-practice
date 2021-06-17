import bcrypt from "bcrypt";
import { customAlphabet } from "nanoid";

// Safe for ArrayBuffer/base64 converting
const alphabet =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const nanoid = customAlphabet(alphabet, 23);

export class Users {
  constructor() {
    this.db = new Map();
  }
  async setNewPassword(id, newPassword) {
    this.getById(id).password = await this.hashPassword(newPassword);
  }
  async setOtpSecret(id, secret) {
    this.getById(id).otpSecret = secret;
  }
  async hashPassword(password) {
    return await bcrypt.hash(password, 10);
  }
  createUserId() {
    return nanoid();
  }
  async add(user) {
    const id = this.createUserId();

    const hashedPassword = await this.hashPassword(user.password);

    const newUser = { ...user, id, password: hashedPassword };
    this.db.set(id, newUser);

    return newUser;
  }
  getById(id) {
    return this.db.get(id);
  }
  getByEmail(email) {
    const mapIter = this.db.values();

    for (let user of mapIter) {
      if (user.email === email) {
        return user;
      }
    }
  }
}
