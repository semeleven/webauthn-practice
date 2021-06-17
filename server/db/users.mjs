import { customAlphabet } from "nanoid";

// Safe for ArrayBuffer/base64 converting
const alphabet =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const nanoid = customAlphabet(alphabet, 23);

export class Users {
  constructor() {
    this.db = new Map();
  }
  addDevice(id, device) {
    this.getById(id).devices.push(device);
  }
  createUserId() {
    return nanoid();
  }
  createUser(user) {
    const id = this.createUserId();

    return { ...user, id, devices: [] };
  }
  add(user) {
    const newUser = user.id ? user : this.createUser(user);

    this.db.set(newUser.id, newUser);

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
